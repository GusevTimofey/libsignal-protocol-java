/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import org.whispersystems.libsignal.util.ByteUtil;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Arrays;

public class DjbECPublicKey implements ECPublicKey {

  private final byte[] publicKey;

  public PublicKey publicKeyElem;

  DjbECPublicKey(byte[] publicKey) {
    this.publicKey = publicKey;
  }

  DjbECPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey.getEncoded();
    this.publicKeyElem = publicKey;
  }

  @Override
  public byte[] serialize() {
    byte[] type = {Curve.DJB_TYPE};
    return ByteUtil.combine(type, publicKey);
  }

  @Override
  public int getType() {
    return Curve.DJB_TYPE;
  }

  @Override
  public PublicKey publicKeyElem() {
    return publicKeyElem;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                      return false;
    if (!(other instanceof DjbECPublicKey)) return false;

    DjbECPublicKey that = (DjbECPublicKey)other;
    return Arrays.equals(this.publicKey, that.publicKey);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(publicKey);
  }

  @Override
  public int compareTo(ECPublicKey another) {
    return new BigInteger(publicKey).compareTo(new BigInteger(((DjbECPublicKey)another).publicKey));
  }

  public byte[] getPublicKey() {
    return publicKey;
  }
}
