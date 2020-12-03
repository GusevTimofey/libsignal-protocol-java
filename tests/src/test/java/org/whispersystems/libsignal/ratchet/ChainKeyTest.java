package org.whispersystems.libsignal.ratchet;

import junit.framework.TestCase;

import org.whispersystems.libsignal.kdf.HKDF;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class ChainKeyTest extends TestCase {

  public void testChainKeyDerivationV2() throws NoSuchAlgorithmException {

    byte[] seed         = {(byte) 0x8a, (byte) 0xb7, (byte) 0x2d, (byte) 0x6f, (byte) 0x4c,
                           (byte) 0xc5, (byte) 0xac, (byte) 0x0d, (byte) 0x38, (byte) 0x7e,
                           (byte) 0xaf, (byte) 0x46, (byte) 0x33, (byte) 0x78, (byte) 0xdd,
                           (byte) 0xb2, (byte) 0x8e, (byte) 0xdd, (byte) 0x07, (byte) 0x38,
                           (byte) 0x5b, (byte) 0x1c, (byte) 0xb0, (byte) 0x12, (byte) 0x50,
                           (byte) 0xc7, (byte) 0x15, (byte) 0x98, (byte) 0x2e, (byte) 0x7a,
                           (byte) 0xd4, (byte) 0x8f};

    byte[] messageKey   = {24, -109, 17, 94, 106, 39, -9, 26, 114, 4, 119, -104, -29, -49, -91, 111, -23, -9, -11, 109, -96, -65, -124, -69, 120, 85, -90, 47, -116, -117, 76, -67};

    byte[] macKey       = {-119, -58, 101, 53, 66, 29, -123, 17, 91, -31, -37, -28, 108, -34, -110, -46, 35, -124, 44, 90, -1, 86, -122, 49, 117, -46, 118, -6, -117, -77, -25, -5};

    byte[] nextChainKey = {24, 76, -70, 55, 82, 63, -51, -59, 26, -116, 78, -98, -22, 58, -70, 0, -5, -41, -28, -122, -75, 49, -100, 54, 104, 47, -87, 111, 117, -122, 0, -19};

    ChainKey chainKey = new ChainKey(HKDF.createFor(2), seed, 0);

    assertTrue(Arrays.equals(chainKey.getKey(), seed));
    assertTrue(Arrays.equals(chainKey.getMessageKeys().getCipherKey().getEncoded(), messageKey));
    assertTrue(Arrays.equals(chainKey.getMessageKeys().getMacKey().getEncoded(), macKey));
    assertTrue(Arrays.equals(chainKey.getNextChainKey().getKey(), nextChainKey));
    assertTrue(chainKey.getIndex() == 0);
    assertTrue(chainKey.getMessageKeys().getCounter() == 0);
    assertTrue(chainKey.getNextChainKey().getIndex() == 1);
    assertTrue(chainKey.getNextChainKey().getMessageKeys().getCounter() == 1);
  }

    public void testChainKeyDerivationV3() throws NoSuchAlgorithmException {

        byte[] seed = {
                (byte) 0x8a, (byte) 0xb7, (byte) 0x2d, (byte) 0x6f, (byte) 0x4c,
                (byte) 0xc5, (byte) 0xac, (byte) 0x0d, (byte) 0x38, (byte) 0x7e,
                (byte) 0xaf, (byte) 0x46, (byte) 0x33, (byte) 0x78, (byte) 0xdd,
                (byte) 0xb2, (byte) 0x8e, (byte) 0xdd, (byte) 0x07, (byte) 0x38,
                (byte) 0x5b, (byte) 0x1c, (byte) 0xb0, (byte) 0x12, (byte) 0x50,
                (byte) 0xc7, (byte) 0x15, (byte) 0x98, (byte) 0x2e, (byte) 0x7a,
                (byte) 0xd4, (byte) 0x8f};

        byte[] messageKey = {
				/* (byte) 0x02*/
                47, 27, 75, 5, 122, 121, -101, -7, -101, 79, -98, -4, -85, 9, -52, -72, -11, -75, 9, 102, -78, 9, 64, 9, -64, 5, -27, 48, -55, 22, 28, 3};

        byte[] macKey = {
                -90, -83, 87, 80, -64, 123, 74, -87, -77, -119, 22, 105, 39, -23, 102, -123, -123, 12, -96, -115, -86, 29, -45, 81, 68, -88, 125, 84, 71, 53, -105, 122};

        byte[] nextChainKey = {
                24, 76, -70, 55, 82, 63, -51, -59, 26, -116, 78, -98, -22, 58, -70, 0, -5, -41, -28, -122, -75, 49, -100, 54, 104, 47, -87, 111, 117, -122, 0, -19};

        ChainKey chainKey = new ChainKey(HKDF.createFor(3), seed, 0);


        assertTrue(Arrays.equals(chainKey.getKey(), seed));
        assertTrue(Arrays.equals(chainKey.getMessageKeys().getCipherKey().getEncoded(), messageKey));
        assertTrue(Arrays.equals(chainKey.getMessageKeys().getMacKey().getEncoded(), macKey));
        assertTrue(Arrays.equals(chainKey.getNextChainKey().getKey(), nextChainKey));
        assertTrue(chainKey.getIndex() == 0);
        assertTrue(chainKey.getMessageKeys().getCounter() == 0);
        assertTrue(chainKey.getNextChainKey().getIndex() == 1);
        assertTrue(chainKey.getNextChainKey().getMessageKeys().getCounter() == 1);
    }
}
