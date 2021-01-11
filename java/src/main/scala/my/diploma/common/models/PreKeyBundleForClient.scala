package my.diploma.common.models

import io.circe.generic.JsonCodec
import io.circe.generic.auto._

@JsonCodec
final case class PreKeyBundleForClient(
  registrationId: Int,
  deviceId: Int,
  preKeyPublic: Array[Byte],
  preKeyId: Int,
  signedPreKeyId: Int,
  SPK: Array[Byte],
  Signature: Array[Byte],
  IK: Array[Byte]
)
