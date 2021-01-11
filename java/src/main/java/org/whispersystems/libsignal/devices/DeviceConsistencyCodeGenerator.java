package org.whispersystems.libsignal.devices;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.whispersystems.libsignal.util.ByteArrayComparator;
import org.whispersystems.libsignal.util.ByteUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class DeviceConsistencyCodeGenerator {

  private static final int CODE_VERSION = 0;

  public static String generateFor(DeviceConsistencyCommitment commitment,
                                   List<DeviceConsistencySignature> signatures)
  {
    try {
      ArrayList<DeviceConsistencySignature> sortedSignatures = new ArrayList<>(signatures);
      Collections.sort(sortedSignatures, new SignatureComparator());

      GOST3411_2012_512Digest digest = new GOST3411_2012_512Digest();

      byte[] codeVersion = ByteUtil.shortToByteArray(CODE_VERSION);
      byte[] commitmentBytes = commitment.toByteArray();

      digest.update(codeVersion, 0, codeVersion.length);
      digest.update(commitmentBytes, 0, commitmentBytes.length);

      for (DeviceConsistencySignature signature : sortedSignatures) {
        byte[] signatureBytes = signature.getVrfOutput();
        digest.update(signatureBytes, 0, signatureBytes.length);
      }

      byte[] hash = new byte[512];

      digest.doFinal(hash, 0);

      String digits = getEncodedChunk(hash, 0) + getEncodedChunk(hash, 5);
      return digits.substring(0, 6);

    } catch (Throwable e) {
      throw new AssertionError(e);
    }
  }

  private static String getEncodedChunk(byte[] hash, int offset) {
    long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
    return String.format("%05d", chunk);
  }


  private static class SignatureComparator extends ByteArrayComparator implements Comparator<DeviceConsistencySignature> {
    @Override
    public int compare(DeviceConsistencySignature first, DeviceConsistencySignature second) {
      return compare(first.getVrfOutput(), second.getVrfOutput());
    }
  }
}
