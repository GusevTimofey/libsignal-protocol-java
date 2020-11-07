/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.kdf;

import com.google.common.primitives.Bytes;
import org.whispersystems.libsignal.my.own.HacGOSTR3411_2012_256;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

public abstract class HKDF {

  private static final int HASH_OUTPUT_SIZE  = 32;

  public static HKDF createFor(int messageVersion) {
    switch (messageVersion) {
      case 2:  return new HKDFv2();
      case 3:  return new HKDFv3();
      default: throw new AssertionError("Unknown version: " + messageVersion);
    }
  }

  public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength) {
    byte[] salt = new byte[HASH_OUTPUT_SIZE];
    return deriveSecrets(inputKeyMaterial, salt, info, outputLength);
  }

  public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
    byte[] prk = extract(salt, inputKeyMaterial);
    return expand(prk, info, outputLength);
  }

  private byte[] extract(byte[] salt, byte[] inputKeyMaterial) {
    try {
      HacGOSTR3411_2012_256 mac = new HacGOSTR3411_2012_256();
      return mac.makeHmac(salt, inputKeyMaterial);
    } catch (Throwable e) {
      throw new AssertionError(e);
    }
  }

  private byte[] expand(byte[] prk, byte[] info, int outputSize) {
    try {
      int                   iterations     = (int) Math.ceil((double) outputSize / (double) HASH_OUTPUT_SIZE);
      byte[]                mixin          = new byte[0];
      ByteArrayOutputStream results        = new ByteArrayOutputStream();
      int                   remainingBytes = outputSize;

      for (int i= getIterationStartOffset();i<iterations + getIterationStartOffset();i++) {
        HacGOSTR3411_2012_256 mac1 = new HacGOSTR3411_2012_256();

        List<Byte> byteList = Bytes.asList(mixin);

        List<Byte> list = new ArrayList<>(byteList);

        if (info != null) {
          List<Byte> byteListL = Bytes.asList(info);
          list.addAll(byteListL);
        }

        list.add((byte)i);

        byte[] stepResult = mac1.makeHmac(prk, Bytes.toArray(list));
        int    stepSize   = Math.min(remainingBytes, stepResult.length);

        results.write(stepResult, 0, stepSize);

        mixin          = stepResult;
        remainingBytes -= stepSize;
      }

      return results.toByteArray();
    } catch (Throwable e) {
      throw new AssertionError(e);
    }
  }

  protected abstract int getIterationStartOffset();

}
