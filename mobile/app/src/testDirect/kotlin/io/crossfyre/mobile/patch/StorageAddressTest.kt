package io.crossfyre.mobile.patch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * What a patch job's answer must carry before anything is uploaded or
 * downloaded. The app's own packages go up to the upload address and an app to
 * install comes down from the download one, so both are https, and the checksum
 * that proves the download is the one the service built is always there.
 */
class StorageAddressTest {

    private val sha = "0123456789abcdef".repeat(4)

    @Test
    fun a_storage_address_must_be_https() {
        assertEquals("r2.example", Patcher.storageUrl("https://r2.example/put?sig=1").host)
        for (bad in listOf("http://r2.example/put", "ftp://r2.example/x", "file:///sdcard/x.zip", "https:///nohost", "not a url", "")) {
            assertThrows(bad, IllegalStateException::class.java) { Patcher.storageUrl(bad) }
        }
    }

    @Test
    fun a_finished_job_must_say_its_checksum() {
        assertEquals(sha, Patcher.checksum(sha))
        assertEquals(sha, Patcher.checksum(sha.uppercase()))
        for (bad in listOf("", "  ", "ab", sha.dropLast(1), sha + "0", sha.dropLast(1) + "g")) {
            assertThrows(bad, IllegalStateException::class.java) { Patcher.checksum(bad) }
        }
    }
}
