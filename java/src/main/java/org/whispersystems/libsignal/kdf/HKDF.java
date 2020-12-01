/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.kdf;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Collections;

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
      HMac mac = new HMac(new GOST3411_2012_256Digest());
      mac.init(new KeyParameter(salt));
      mac.update(inputKeyMaterial, 0, inputKeyMaterial.length);
      byte[] result = new byte[32];
      mac.doFinal(result, 0);

      System.out.println("=========");
      System.out.println("THIS IS extract: " + Arrays.toString(result));
      System.out.println("=========");

      return result;
    } catch (Throwable e) {
      throw new AssertionError(e);
    }
  }

  private byte[] expand(byte[] prk, byte[] info, int outputSize) {
    try {
      int                   iterations     = (int) Math.ceil((double) outputSize / (double) HASH_OUTPUT_SIZE);
      ByteArrayOutputStream results        = new ByteArrayOutputStream();
      byte[]                mixin          = new byte[0];
      int                   remainingBytes = outputSize;

      for (int i= getIterationStartOffset();i<iterations + getIterationStartOffset();i++) {
        HMac mac = new HMac(new GOST3411_2012_256Digest());
        mac.init(new KeyParameter(prk));
        mac.update(mixin, 0, mixin.length);

        if (info != null) {
          mac.update(info, 0, info.length);
        }

        mac.update((byte)i);

        byte[] stepResult = new byte[32];
        mac.doFinal(stepResult, 0);

        System.out.println("=========");
        System.out.println("This is expand. Step is:" + i +". Step result: " + Arrays.toString(stepResult));
        System.out.println("=========");

        int    stepSize   = Math.min(remainingBytes, stepResult.length);

        System.out.println("=========");
        System.out.println("This is expand. Step size is:" + stepSize);
        System.out.println("=========");

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
