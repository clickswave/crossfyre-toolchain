package io.crossfyre.tracer

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/** What an APK says it is, read from its own binary AndroidManifest.xml.
 *
 * `PackageManager.getPackageArchiveInfo` is the obvious way to ask this, and it
 * is the wrong one here. It parses a single APK in isolation, and a base that
 * declares `android:isSplitRequired="true"` cannot be validated in isolation, so
 * the platform parser returns null for the BASE as well as for its config
 * splits. Apollo (`requiredSplitTypes="base__density"`) came back correctly
 * patched, correctly signed and correctly aligned, and was rejected as "no
 * installable build" because nothing in the set would parse. AfterShip, whose
 * base requires no split, worked, which is why the assumption survived.
 *
 * Reading the manifest ourselves also checks something the old path could not:
 * a config split's package. Previously splits were only checked for being real
 * ZIPs, and their identity was left to PackageInstaller at commit time.
 */
object Axml {

    /** The `package` and `split` a manifest declares. A base has no `split`. */
    data class Identity(val packageName: String, val split: String?)

    private const val AXML_MAGIC = 0x00080003
    private const val CHUNK_STRING_POOL = 0x0001
    private const val CHUNK_START_ELEMENT = 0x0102
    private const val UTF8_FLAG = 0x100
    private const val NO_ENTRY = -1 // 0xffffffff: "no string" / "no namespace"

    /** Null when the file is not a ZIP, has no manifest, or the manifest is not
     *  parseable - all of which mean "do not install this". */
    fun identify(apk: File): Identity? = runCatching {
        val raw = ZipFile(apk).use { z ->
            val e = z.getEntry("AndroidManifest.xml") ?: return null
            z.getInputStream(e).use { it.readBytes() }
        }
        parse(raw)
    }.getOrNull()

    private fun parse(raw: ByteArray): Identity? {
        val b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        if (b.capacity() < 8 || b.getInt(0) != AXML_MAGIC) return null

        var pool: List<String>? = null
        var off = 8
        while (off + 8 <= b.capacity()) {
            val type = b.getShort(off).toInt() and 0xffff
            val size = b.getInt(off + 4)
            if (size <= 0 || off + size > b.capacity()) return null
            when (type) {
                CHUNK_STRING_POOL -> pool = readStringPool(b, off)
                CHUNK_START_ELEMENT -> {
                    val strings = pool ?: return null
                    // Element header is 16 bytes, then ns, name, then the
                    // attribute block's offset/stride/count.
                    val name = b.getInt(off + 20)
                    val attrStart = b.getShort(off + 24).toInt() and 0xffff
                    val attrSize = b.getShort(off + 26).toInt() and 0xffff
                    val attrCount = b.getShort(off + 28).toInt() and 0xffff
                    if (strings.getOrNull(name) != "manifest") return null // manifest is first
                    var pkg: String? = null
                    var split: String? = null
                    for (i in 0 until attrCount) {
                        val a = off + 16 + attrStart + i * attrSize
                        if (a + 12 > b.capacity()) return null
                        val ans = b.getInt(a)
                        val an = b.getInt(a + 4)
                        val araw = b.getInt(a + 8)
                        // `package` and `split` carry no namespace, which also
                        // stops an android:-prefixed lookalike from matching.
                        if (ans != NO_ENTRY) continue
                        when (strings.getOrNull(an)) {
                            "package" -> pkg = if (araw != NO_ENTRY) strings.getOrNull(araw) else null
                            "split" -> split = if (araw != NO_ENTRY) strings.getOrNull(araw) else null
                        }
                    }
                    return pkg?.takeIf { it.isNotBlank() }?.let { Identity(it, split?.takeIf(String::isNotBlank)) }
                }
            }
            off += size
        }
        return null
    }

    private fun readStringPool(b: ByteBuffer, off: Int): List<String>? {
        val count = b.getInt(off + 8)
        val flags = b.getInt(off + 16)
        val dataStart = off + b.getInt(off + 20)
        if (count < 0 || count > 1 shl 20) return null
        val utf8 = (flags and UTF8_FLAG) != 0
        val out = ArrayList<String>(count)
        for (i in 0 until count) {
            var p = dataStart + b.getInt(off + 28 + i * 4)
            if (p < 0 || p >= b.capacity()) return null
            out.add(if (utf8) readUtf8(b, p) else readUtf16(b, p))
        }
        return out
    }

    /** Both length fields are 1 byte, or 2 with the high bit set on the first. */
    private fun readUtf8(b: ByteBuffer, start: Int): String {
        var p = start
        var n = b.get(p).toInt() and 0xff; p++
        if (n and 0x80 != 0) p++ // utf16 length, unused
        n = b.get(p).toInt() and 0xff; p++
        if (n and 0x80 != 0) {
            n = ((n and 0x7f) shl 8) or (b.get(p).toInt() and 0xff); p++
        }
        val bytes = ByteArray(n)
        for (i in 0 until n) bytes[i] = b.get(p + i)
        return String(bytes, Charsets.UTF_8)
    }

    private fun readUtf16(b: ByteBuffer, start: Int): String {
        var p = start
        var n = b.getShort(p).toInt() and 0xffff; p += 2
        if (n and 0x8000 != 0) {
            n = ((n and 0x7fff) shl 16) or (b.getShort(p).toInt() and 0xffff); p += 2
        }
        val chars = CharArray(n)
        for (i in 0 until n) chars[i] = b.getChar(p + i * 2)
        return String(chars)
    }
}
