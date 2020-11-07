package org.whispersystems.libsignal.devices;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.IdentityKeyComparator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DeviceConsistencyCommitment {

  private static final String VERSION = "DeviceConsistencyCommitment_V0";

  private final int generation;
  private final byte[] serialized;

  public DeviceConsistencyCommitment(int generation, List<IdentityKey> identityKeys) {
    try {
      ArrayList<IdentityKey> sortedIdentityKeys = new ArrayList<>(identityKeys);
      Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

      GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();

      byte[] versionBytes = VERSION.getBytes();
      byte[] generationBytes = ByteUtil.intToByteArray(generation);

      digest.update(versionBytes, 0, versionBytes.length);
      digest.update(generationBytes, 0, generationBytes.length);

      for (IdentityKey commitment : sortedIdentityKeys) {
        byte[] commitmentBytes = commitment.getPublicKey().serialize();
        digest.update(commitmentBytes, 0, commitmentBytes.length);
      }

      byte[] hash = new byte[256];
      digest.doFinal(hash, 0);

      this.generation = generation;
      this.serialized = hash;
    } catch (Throwable e) {
      throw new AssertionError(e);
    }
  }

  public byte[] toByteArray() {
    return serialized;
  }

  public int getGeneration() {
    return generation;
  }


}
