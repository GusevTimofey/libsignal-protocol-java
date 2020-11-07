/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ratchet;


import com.google.common.primitives.Bytes;
import org.whispersystems.libsignal.kdf.DerivedMessageSecrets;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.my.own.HacGOSTR3411_2012_256;

import java.util.List;

public class ChainKey {

  private static final byte[] MESSAGE_KEY_SEED = {0x01};
  private static final byte[] CHAIN_KEY_SEED   = {0x02};

  private final HKDF   kdf;
  private final byte[] key;
  private final int    index;

  public ChainKey(HKDF kdf, byte[] key, int index) {
    this.kdf   = kdf;
    this.key   = key;
    this.index = index;
  }

  public byte[] getKey() {
    return key;
  }

  public int getIndex() {
    return index;
  }

  public ChainKey getNextChainKey() {
    byte[] nextKey = getBaseMaterial(CHAIN_KEY_SEED);
    return new ChainKey(kdf, nextKey, index + 1);
  }

  public MessageKeys getMessageKeys() {
    byte[]                inputKeyMaterial = getBaseMaterial(MESSAGE_KEY_SEED);
    byte[]                keyMaterialBytes = kdf.deriveSecrets(inputKeyMaterial, "WhisperMessageKeys".getBytes(), DerivedMessageSecrets.SIZE);
    DerivedMessageSecrets keyMaterial      = new DerivedMessageSecrets(keyMaterialBytes);

    return new MessageKeys(keyMaterial.getCipherKey(), keyMaterial.getMacKey(), keyMaterial.getIv(), index);
  }

  private byte[] getBaseMaterial(byte[] seed) {
    try {
      HacGOSTR3411_2012_256 mac1 = new HacGOSTR3411_2012_256();
      List<Byte> list = Bytes.asList(seed);

      return mac1.makeHmac(key, Bytes.toArray(list));
    } catch (Throwable e) {
      throw new AssertionError(e);
    }
  }
}
