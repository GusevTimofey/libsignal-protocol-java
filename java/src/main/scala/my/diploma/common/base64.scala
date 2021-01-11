package my.diploma.common

import java.nio.charset.StandardCharsets
import java.util.Base64
import cats.syntax.either._

object base64 {

  def toBase64Url(s: Array[Byte]): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(s)

  def fromBase64(s: String): Array[Byte] =
    Base64.getDecoder.decode(s)

}
