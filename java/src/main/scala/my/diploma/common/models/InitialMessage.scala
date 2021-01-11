package my.diploma.common.models

import io.circe.generic.JsonCodec

@JsonCodec
final case class InitialMessage(preKeyBundleForClient: PreKeyBundleForClient, message: Array[Byte])
