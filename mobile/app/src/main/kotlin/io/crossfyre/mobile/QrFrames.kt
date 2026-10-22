package io.crossfyre.mobile

import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Find a QR code in a camera frame, on the phone.
 *
 * Only the brightness plane is read: a QR code is black and white, and the Y
 * plane of a YUV frame is exactly that, without converting the frame. A QR code
 * reads in any orientation, so the frame is not rotated first.
 */
object QrFrames {
    private val reader = QRCodeReader()
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )

    fun decode(proxy: ImageProxy): String? {
        val plane = proxy.planes.firstOrNull() ?: return null
        val w = proxy.width
        val h = proxy.height
        val y = tight(plane.buffer, plane.rowStride, plane.pixelStride, w, h)
        return decode(PlanarYUVLuminanceSource(y, w, h, 0, 0, w, h, false))
    }

    /**
     * The brightness plane as exactly width x height bytes.
     *
     * A camera's rows are padded out to a stride, and the last row usually is
     * not, so the buffer is shorter than stride x height. Handed over as it is,
     * ZXing refuses every frame as not fitting its own dimensions.
     */
    fun tight(buf: java.nio.ByteBuffer, rowStride: Int, pixelStride: Int, w: Int, h: Int): ByteArray {
        val out = ByteArray(w * h)
        val src = buf.duplicate()
        for (row in 0 until h) {
            val start = row * rowStride
            if (pixelStride == 1) {
                src.position(start)
                src.get(out, row * w, minOf(w, src.remaining()))
            } else {
                for (col in 0 until w) {
                    val i = start + col * pixelStride
                    if (i < src.limit()) out[row * w + col] = src.get(i)
                }
            }
        }
        return out
    }

    /** The decode itself, apart from the camera, so it can be tested with a drawn code. */
    fun decode(source: LuminanceSource): String? = try {
        reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (e: NotFoundException) {
        null
    } catch (e: com.google.zxing.ChecksumException) {
        null
    } catch (e: com.google.zxing.FormatException) {
        null
    } finally {
        reader.reset()
    }
}
