/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.GOST3410KeyPairGenerator;
import org.bouncycastle.crypto.params.GOST3410PrivateKeyParameters;
import org.bouncycastle.crypto.params.GOST3410PublicKeyParameters;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.ECGOST2012SignatureSpi512;
import org.bouncycastle.jcajce.provider.asymmetric.gost.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.provider.asymmetric.gost.SignatureSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.curve25519.VrfSignatureVerificationFailedException;
import org.whispersystems.libsignal.InvalidKeyException;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.whispersystems.curve25519.Curve25519.BEST;

public class Curve {

  public  static final int DJB_TYPE   = 0x05;

  public static boolean isNative() {
    ECGOST2012SignatureSpi512 a = new ECGOST2012SignatureSpi512();

    return Curve25519.getInstance(BEST).isNative();
  }

  public static ECKeyPair generateKeyPair() {
    KeyPair pair = new KeyPairGeneratorSpi().generateKeyPair();

    return new ECKeyPair(
            new DjbECPublicKey(pair.getPublic()),
            new DjbECPrivateKey(pair.getPrivate().getEncoded())
    );
  }

  public static ECPublicKey decodePoint(byte[] bytes, int offset)
      throws InvalidKeyException
  {
    if (bytes == null || bytes.length - offset < 1) {
      throw new InvalidKeyException("No key type identifier");
    }

    int type = bytes[offset] & 0xFF;

    //if (type == Curve.DJB_TYPE) {
      if (bytes.length - offset < 33) {
        throw new InvalidKeyException("Bad key length: " + bytes.length);
      }

      byte[] keyBytes = new byte[32];
      System.arraycopy(bytes, offset + 1, keyBytes, 0, keyBytes.length);
      return new DjbECPublicKey(keyBytes);
    //}
    //throw new InvalidKeyException("Bad key type: " + type);
  }

  public static ECPrivateKey decodePrivatePoint(byte[] bytes) {
    return new DjbECPrivateKey(bytes);
  }

  public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
      throws InvalidKeyException
  {

    if (publicKey == null) {
      throw new InvalidKeyException("public value is null");
    }

    if (privateKey == null) {
      throw new InvalidKeyException("private value is null");
    }

    if (publicKey.getType() != privateKey.getType()) {
      throw new InvalidKeyException("Public and private keys must be of the same type!");
    }

    if (publicKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
              .calculateAgreement(((DjbECPublicKey) publicKey).getPublicKey(),
                      ((DjbECPrivateKey) privateKey).getPrivateKey());
    } else {
      throw new InvalidKeyException("Unknown type: " + publicKey.getType());
    }
  }

  public static boolean verifySignature(final ECPublicKey signingKey, byte[] message, byte[] signature)
          throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, java.security.InvalidKeyException, SignatureException {

    if (signingKey == null || signature == null || message == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    Security.addProvider(new BouncyCastleProvider());
    Signature signer = Signature.getInstance("ECGOST3410", "BC");

    if (signingKey.getType() == DJB_TYPE) {
      signer.initVerify(signingKey.publicKeyElem());
      signer.update(message);
      signer.verify(signature);
      return signer.verify(signature);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

  public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
          throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, java.security.InvalidKeyException, SignatureException {

    if (signingKey == null || message == null) {
      throw new InvalidKeyException("Values must not be null");
    }
    Security.addProvider(new BouncyCastleProvider());
    Signature signer = Signature.getInstance("ECGOST3410", "BC");
    KeyFactory f = KeyFactory.getInstance("ECGOST3410", "BC");


    if (signingKey.getType() == DJB_TYPE) {
      signer.initSign(signingKey.key());
      signer.update(message);
      signer.sign();
      return signer.sign();
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

  public static byte[] calculateVrfSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    if (signingKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
                       .calculateVrfSignature(((DjbECPrivateKey)signingKey).getPrivateKey(), message);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

  public static byte[] verifyVrfSignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException, VrfSignatureVerificationFailedException
  {
    if (signingKey == null || message == null || signature == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    if (signingKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
                       .verifyVrfSignature(((DjbECPublicKey) signingKey).getPublicKey(), message, signature);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

}
