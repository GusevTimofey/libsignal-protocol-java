package org.whispersystems.libsignal.fingerprint;

import junit.framework.TestCase;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

import java.util.Arrays;

public class NumericFingerprintGeneratorTest extends TestCase {

  private static final byte[] ALICE_IDENTITY = {(byte) 0x05, (byte) 0x06, (byte) 0x86, (byte) 0x3b, (byte) 0xc6, (byte) 0x6d, (byte) 0x02, (byte) 0xb4, (byte) 0x0d, (byte) 0x27, (byte) 0xb8, (byte) 0xd4, (byte) 0x9c, (byte) 0xa7, (byte) 0xc0, (byte) 0x9e, (byte) 0x92, (byte) 0x39, (byte) 0x23, (byte) 0x6f, (byte) 0x9d, (byte) 0x7d, (byte) 0x25, (byte) 0xd6, (byte) 0xfc, (byte) 0xca, (byte) 0x5c, (byte) 0xe1, (byte) 0x3c, (byte) 0x70, (byte) 0x64, (byte) 0xd8, (byte) 0x68};
  private static final byte[] BOB_IDENTITY   = {(byte) 0x05, (byte) 0xf7, (byte) 0x81, (byte) 0xb6, (byte) 0xfb, (byte) 0x32, (byte) 0xfe, (byte) 0xd9, (byte) 0xba, (byte) 0x1c, (byte) 0xf2, (byte) 0xde, (byte) 0x97, (byte) 0x8d, (byte) 0x4d, (byte) 0x5d, (byte) 0xa2, (byte) 0x8d, (byte) 0xc3, (byte) 0x40, (byte) 0x46, (byte) 0xae, (byte) 0x81, (byte) 0x44, (byte) 0x02, (byte) 0xb5, (byte) 0xc0, (byte) 0xdb, (byte) 0xd9, (byte) 0x6f, (byte) 0xda, (byte) 0x90, (byte) 0x7b};

  private static final int    VERSION_1                      = 1;
  private static final String DISPLAYABLE_FINGERPRINT_V1     = "022133347500206633894762269945071969576196780953621593174606";
  private static final byte[] ALICE_SCANNABLE_FINGERPRINT_V1 = new byte[]{
          8, 1, 18, 34, 10, 32, -42, -3, 11, -83, 37, -103, -26, 112, -110, 99, -58, 53, -68, -13, -82, 87, -48, 122, -52, 93, 22, -28, 95, -116, 102, -44, 122, 74, -127, -103, -47, 95, 26, 34, 10, 32, 29, 112, 70, 77, -68, -67, 3, 26, -95, 17, 73, -106, -64, 73, -84, -113, 96, 32, -14, -62, 16, 16, -69, -67, 123, 34, 25, 103, 23, 46, -81, -53  };
  private static final byte[] BOB_SCANNABLE_FINGERPRINT_V1   = new byte[]{
          8, 1, 18, 34, 10, 32, 29, 112, 70, 77, -68, -67, 3, 26, -95, 17, 73, -106, -64, 73, -84, -113, 96, 32, -14, -62, 16, 16, -69, -67, 123, 34, 25, 103, 23, 46, -81, -53, 26, 34, 10, 32, -42, -3, 11, -83, 37, -103, -26, 112, -110, 99, -58, 53, -68, -13, -82, 87, -48, 122, -52, 93, 22, -28, 95, -116, 102, -44, 122, 74, -127, -103, -47, 95  };
  private static final int    VERSION_2                      = 2;
  private static final String DISPLAYABLE_FINGERPRINT_V2     = DISPLAYABLE_FINGERPRINT_V1;
  private static final byte[] ALICE_SCANNABLE_FINGERPRINT_V2 = new byte[]{
          8, 2, 18, 34, 10, 32, -42, -3, 11, -83, 37, -103, -26, 112, -110, 99, -58, 53, -68, -13, -82, 87, -48, 122, -52, 93, 22, -28, 95, -116, 102, -44, 122, 74, -127, -103, -47, 95, 26, 34, 10, 32, 29, 112, 70, 77, -68, -67, 3, 26, -95, 17, 73, -106, -64, 73, -84, -113, 96, 32, -14, -62, 16, 16, -69, -67, 123, 34, 25, 103, 23, 46, -81, -53
  };
  private static final byte[] BOB_SCANNABLE_FINGERPRINT_V2   = new byte[]{
          8, 2, 18, 34, 10, 32, 29, 112, 70, 77, -68, -67, 3, 26, -95, 17, 73, -106, -64, 73, -84, -113, 96, 32, -14, -62, 16, 16, -69, -67, 123, 34, 25, 103, 23, 46, -81, -53, 26, 34, 10, 32, -42, -3, 11, -83, 37, -103, -26, 112, -110, 99, -58, 53, -68, -13, -82, 87, -48, 122, -52, 93, 22, -28, 95, -116, 102, -44, 122, 74, -127, -103, -47, 95  };
  public void testVectorsVersion1() throws Exception {
    IdentityKey aliceIdentityKey = new IdentityKey(ALICE_IDENTITY, 0);
    IdentityKey bobIdentityKey   = new IdentityKey(BOB_IDENTITY, 0);
    byte[]      aliceStableId    = "+14152222222".getBytes();
    byte[]      bobStableId      = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprint = generator.createFor(VERSION_1,
                                                      aliceStableId, aliceIdentityKey,
                                                      bobStableId, bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_1,
                                                     bobStableId, bobIdentityKey,
                                                     aliceStableId, aliceIdentityKey);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V1);
    assertEquals(bobFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V1);

    System.out.println("This is a: " + Arrays.toString(aliceFingerprint.getScannableFingerprint().getSerialized()));
    System.out.println("This is b: " + Arrays.toString(bobFingerprint.getScannableFingerprint().getSerialized()));

    System.out.println("a:" + aliceFingerprint.getScannableFingerprint().getSerialized().length + " -> " + ALICE_SCANNABLE_FINGERPRINT_V1.length);

    System.out.println();

    assertTrue(Arrays.equals(aliceFingerprint.getScannableFingerprint().getSerialized(), ALICE_SCANNABLE_FINGERPRINT_V1));
    assertTrue(Arrays.equals(bobFingerprint.getScannableFingerprint().getSerialized(), BOB_SCANNABLE_FINGERPRINT_V1));
  }

  public void testVectorsVersion2() throws Exception {
    IdentityKey aliceIdentityKey = new IdentityKey(ALICE_IDENTITY, 0);
    IdentityKey bobIdentityKey   = new IdentityKey(BOB_IDENTITY, 0);
    byte[]      aliceStableId    = "+14152222222".getBytes();
    byte[]      bobStableId      = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprint = generator.createFor(VERSION_2,
                                                      aliceStableId, aliceIdentityKey,
                                                      bobStableId, bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_2,
                                                     bobStableId, bobIdentityKey,
                                                     aliceStableId, aliceIdentityKey);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V2);
    assertEquals(bobFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V2);

    System.out.println(Arrays.toString(aliceFingerprint.getScannableFingerprint().getSerialized()));
    System.out.println(Arrays.toString(bobFingerprint.getScannableFingerprint().getSerialized()));

    System.out.println("first: " + Arrays.toString(aliceFingerprint.getScannableFingerprint().getSerialized()));
    System.out.println("second: " + Arrays.toString(ALICE_SCANNABLE_FINGERPRINT_V2));
    System.out.println(Arrays.equals(aliceFingerprint.getScannableFingerprint().getSerialized(), ALICE_SCANNABLE_FINGERPRINT_V2));

    assertTrue(Arrays.equals(aliceFingerprint.getScannableFingerprint().getSerialized(), ALICE_SCANNABLE_FINGERPRINT_V2));
    assertTrue(Arrays.equals(bobFingerprint.getScannableFingerprint().getSerialized(), BOB_SCANNABLE_FINGERPRINT_V2));
  }

  public void testMatchingFingerprints() throws FingerprintVersionMismatchException, FingerprintIdentifierMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey   = new IdentityKey(bobKeyPair.getPublicKey());

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION_1,
                                                                       "+14152222222".getBytes(), aliceIdentityKey,
                                                                       "+14153333333".getBytes(), bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_1,
                                                     "+14153333333".getBytes(), bobIdentityKey,
                                                     "+14152222222".getBytes(), aliceIdentityKey);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                 bobFingerprint.getDisplayableFingerprint().getDisplayText());

    assertTrue(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertTrue(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText().length(), 60);
  }

  public void testMismatchingFingerprints() throws FingerprintVersionMismatchException, FingerprintIdentifierMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();
    ECKeyPair mitmKeyPair  = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey   = new IdentityKey(bobKeyPair.getPublicKey());
    IdentityKey mitmIdentityKey  = new IdentityKey(mitmKeyPair.getPublicKey());

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION_1,
                                                                       "+14152222222".getBytes(), aliceIdentityKey,
                                                                       "+14153333333".getBytes(), mitmIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_1,
                                                     "+14153333333".getBytes(), bobIdentityKey,
                                                     "+14152222222".getBytes(), aliceIdentityKey);

    assertFalse(aliceFingerprint.getDisplayableFingerprint().getDisplayText().equals(
                bobFingerprint.getDisplayableFingerprint().getDisplayText()));

    assertFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

  public void testMismatchingIdentifiers() throws FingerprintVersionMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey   = new IdentityKey(bobKeyPair.getPublicKey());

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION_1,
                                                                       "+141512222222".getBytes(), aliceIdentityKey,
                                                                       "+14153333333".getBytes(), bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor(VERSION_1,
                                                     "+14153333333".getBytes(), bobIdentityKey,
                                                     "+14152222222".getBytes(), aliceIdentityKey);

    assertFalse(aliceFingerprint.getDisplayableFingerprint().getDisplayText().equals(
                bobFingerprint.getDisplayableFingerprint().getDisplayText()));

    assertFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

  public void testDifferentVersionsMakeSameFingerPrintsButDifferentScannable() throws Exception {
    IdentityKey aliceIdentityKey = new IdentityKey(ALICE_IDENTITY, 0);
    IdentityKey bobIdentityKey   = new IdentityKey(BOB_IDENTITY, 0);
    byte[]      aliceStableId    = "+14152222222".getBytes();
    byte[]      bobStableId      = "+14153333333".getBytes();

    NumericFingerprintGenerator generator          = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprintV1 = generator.createFor(VERSION_1,
                                                         aliceStableId, aliceIdentityKey,
                                                         bobStableId, bobIdentityKey);

    Fingerprint aliceFingerprintV2 = generator.createFor(VERSION_2,
                                                         aliceStableId, aliceIdentityKey,
                                                         bobStableId, bobIdentityKey);


    assertTrue(aliceFingerprintV1.getDisplayableFingerprint().getDisplayText().equals(
               aliceFingerprintV2.getDisplayableFingerprint().getDisplayText()));

    assertFalse(Arrays.equals(aliceFingerprintV1.getScannableFingerprint().getSerialized(),
                              aliceFingerprintV2.getScannableFingerprint().getSerialized()));
  }

}
