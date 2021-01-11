import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.Security
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

Security.addProvider(new BouncyCastleProvider)

val key = new SecretKeySpec(
  Array(
    20, 103, 41, -17, -63, 106, -125, -2, 95, -74, 34, 66, -62, -104, 118, 108, -117, 19, 80, -5, 33, 84, -34, 124,
    -107, 49, -127, -87, 11, -81, -31, 117
  ),
  "GOST3412-2015"
)

val iv = new IvParameterSpec(
  Array(62, 28, 66, -104, -8, 38, -70, 30, -1, -126, 58, 44, -54, -51, -48, 7)
)

val encryptedMessage = Array[Byte](
  -47, 16, 70, 5, 91, 103, -109, 43, 51, 46, 114, 22, -5, -12, -76, -94, 10, 66, 116, -75, -76, -74, -7, -120, -1, 109,
  20, 106, -58, 22, 30, -118, -69, 38, -95, 44, 81, -27, -86, 90, -128, -27, -102, 95, -120, 29, 54, 122, 99, -56, -21,
  118, 46, -48, 0, -6, -22, 98, -94, 28, 56, -128, -60, -76, -80, 76, 52, 0, 102, -20, -82, 31, 14, -6, 85, -44, 82,
  104, 63, -109, -48, -53, -38, 5, -106, -18, -87, 89, 68, -23, 70, -40, -62, 120, -15, -113
)

val cipher: Cipher = Cipher.getInstance("GOST3412-2015/CBC/PKCS5Padding")
cipher.init(Cipher.DECRYPT_MODE, key, iv)
val res            = cipher.doFinal(encryptedMessage)
val resultedString = new String(res)
