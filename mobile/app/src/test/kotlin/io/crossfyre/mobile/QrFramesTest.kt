package io.crossfyre.mobile

import com.google.zxing.BarcodeFormat
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The scanner's decoder reads a pairing code drawn the way the dashboard draws one, with nothing but the phone. */
class QrFramesTest {

    private fun frame(text: String, quarterTurns: Int = 0): RGBLuminanceSource {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 240, 240)
        val w = m.width
        val px = IntArray(w * w)
        for (y in 0 until w) for (x in 0 until w) {
            // Rotate the drawn code, as a phone held sideways sees it.
            val (sx, sy) = when (quarterTurns % 4) {
                1 -> y to (w - 1 - x)
                2 -> (w - 1 - x) to (w - 1 - y)
                3 -> (w - 1 - y) to x
                else -> x to y
            }
            px[y * w + x] = if (m.get(sx, sy)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
        }
        return RGBLuminanceSource(w, w, px)
    }

    @Test
    fun a_pairing_code_is_read_in_any_orientation() {
        val payload = """{"api_url":"https://crossfyre.io","workflow_id":"wf-1","token":"cfxt_abc"}"""
        for (turns in 0..3) assertEquals(payload, QrFrames.decode(frame(payload, turns)))
    }

    @Test
    fun a_frame_with_no_code_is_nothing_rather_than_an_error() {
        val blank = RGBLuminanceSource(64, 64, IntArray(64 * 64) { 0xFFFFFFFF.toInt() })
        assertNull(QrFrames.decode(blank))
    }
}

class QrPlaneTest {
    @Test
    fun a_padded_plane_whose_last_row_is_short_is_read_as_width_by_height() {
        // 3x3 image, rows padded to 5, and the last row not padded at all.
        val raw = byteArrayOf(1, 2, 3, 0, 0, 4, 5, 6, 0, 0, 7, 8, 9)
        val y = QrFrames.tight(java.nio.ByteBuffer.wrap(raw), rowStride = 5, pixelStride = 1, w = 3, h = 3)
        assertEquals((1..9).map { it.toByte() }, y.toList())
    }
}
