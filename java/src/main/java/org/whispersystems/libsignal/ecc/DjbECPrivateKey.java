/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import java.security.PrivateKey;
import java.security.PublicKey;

public class DjbECPrivateKey implements ECPrivateKey {

  private final byte[] privateKey;

  private PrivateKey privKey;

  DjbECPrivateKey(byte[] privateKey) {
    this.privateKey = privateKey;
  }

  DjbECPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey.getEncoded();
    this.privKey = privateKey;
  }

  @Override
  public byte[] serialize() {
    return privateKey;
  }

  @Override
  public int getType() {
    return Curve.DJB_TYPE;
  }

  @Override
  public PrivateKey key() {
    return privKey;
  }

  public byte[] getPrivateKey() {
    return privateKey;
  }
}
