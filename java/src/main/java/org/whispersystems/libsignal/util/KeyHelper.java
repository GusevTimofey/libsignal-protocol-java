/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.util;

import com.google.common.primitives.Ints;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Helper class for generating keys of different types.
 *
 * @author Moxie Marlinspike
 */
public class KeyHelper {

  private KeyHelper() {}

  /**
   * Generate an identity key pair.  Clients should only do this once,
   * at install time.
   *
   * @return the generated IdentityKeyPair.
   */
  public static IdentityKeyPair generateIdentityKeyPair() {
    System.out.println("== Generate IKa ==");
    ECKeyPair   keyPair   = Curve.generateKeyPair();
    System.out.println("== Finish Generate IKa ==");
    System.out.println("qwe:" + Arrays.toString(keyPair.getPublicKey().serialize()));
    IdentityKey publicKey = new IdentityKey(keyPair.getPublicKey());
    System.out.println("~~IK111: " + Arrays.toString(publicKey.serialize()) + " ~~~~" );
    System.out.println("~~IK111: " + Arrays.toString(publicKey.getPublicKey().serialize()) + " ~~~~" );
    IdentityKeyPair kp = new IdentityKeyPair(publicKey, keyPair.getPrivateKey());
    System.out.println("~~IK222: " + Arrays.toString(kp.getPublicKey().serialize()) + " ~~~~" );
    return kp;
  }

  /**
   * Generate a registration ID.  Clients should only do this once,
   * at install time.
   *
   * @param extendedRange By default (false), the generated registration
   *                      ID is sized to require the minimal possible protobuf
   *                      encoding overhead. Specify true if the caller needs
   *                      the full range of MAX_INT at the cost of slightly
   *                      higher encoding overhead.
   * @return the generated registration ID.
   */
  public static int generateRegistrationId(boolean extendedRange) {
    DigestRandomGenerator rng = new DigestRandomGenerator(new GOST3411_2012_256Digest());
    byte[] result;
    if (extendedRange){
        result = new byte[32];
      }
      else {
        result = new byte[4];
      }
    rng.nextBytes(result);
    return Ints.fromByteArray(result) + 1;
  }

  public static int getRandomSequence(int max) {
    DigestRandomGenerator rng = new DigestRandomGenerator(new GOST3411_2012_256Digest());
    int size = Ints.toByteArray(max).length;
    byte[] result = new byte[size];
    rng.nextBytes(result);
    return Ints.fromByteArray(result);
  }

  /**
   * Generate a list of PreKeys.  Clients should do this at install time, and
   * subsequently any time the list of PreKeys stored on the server runs low.
   * <p>
   * PreKey IDs are shorts, so they will eventually be repeated.  Clients should
   * store PreKeys in a circular buffer, so that they are repeated as infrequently
   * as possible.
   *
   * @param start The starting PreKey ID, inclusive.
   * @param count The number of PreKeys to generate.
   * @return the list of generated PreKeyRecords.
   */
  public static List<PreKeyRecord> generatePreKeys(int start, int count) {
    List<PreKeyRecord> results = new LinkedList<>();

    start--;

    for (int i=0;i<count;i++) {
      results.add(new PreKeyRecord(((start + i) % (Medium.MAX_VALUE-1)) + 1, Curve.generateKeyPair()));
    }

    return results;
  }

  /**
   * Generate a signed PreKey
   *
   * @param identityKeyPair The local client's identity key pair.
   * @param signedPreKeyId The PreKey id to assign the generated signed PreKey
   *
   * @return the generated signed PreKey
   * @throws InvalidKeyException when the provided identity key is invalid
   */
  public static SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKeyPair, int signedPreKeyId)
      throws InvalidKeyException
  {
    ECKeyPair keyPair   = Curve.generateKeyPair();
    byte[]    signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());

    return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
  }


  public static ECKeyPair generateSenderSigningKey() {
    return Curve.generateKeyPair();
  }

  public static byte[] generateSenderKey() {
    DigestRandomGenerator rng = new DigestRandomGenerator(new GOST3411_2012_256Digest());
    byte[] key = new byte[32];
    rng.nextBytes(key);
    return key;
  }

  public static int generateSenderKeyId() {
    DigestRandomGenerator rng = new DigestRandomGenerator(new GOST3411_2012_256Digest());
    byte[] result = new byte[32];
    rng.nextBytes(result);
    return Ints.fromByteArray(result);
  }

}
