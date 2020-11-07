package org.whispersystems.libsignal.my.own

import scorex.crypto.hash.Stribog256._

final class HacGOSTR3411_2012_256 {

  def makeHmac(key: Array[Byte], input: Array[Byte]): Array[Byte] = {

    val kXorOpad: Array[Byte] = key.map(_ ^ 0x36)
    val kXorIpad: Array[Byte] = key.map(_ ^ 0x5C)

    val orLeftRes: Array[Byte] = kXorIpad.appendedAll(input)
    val orLeftResHash: Array[Byte] = hash(orLeftRes).array

    val leftOrRight = kXorOpad.appendedAll(orLeftResHash)

    hash(leftOrRight).array
  }

}
