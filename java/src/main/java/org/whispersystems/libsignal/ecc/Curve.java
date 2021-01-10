/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;

import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.crypto.agreement.ECVKOAgreement;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.VrfSignatureVerificationFailedException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.ByteUtil;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.whispersystems.curve25519.Curve25519.BEST;

public class Curve {

  public static final int DJB_TYPE = 0x05;

  public static boolean isNative() {
    return Curve25519.getInstance(BEST).isNative();
  }


  public static ECKeyPair generateKeyPair() {
    KeyPairGeneratorSpi ECGOST3410 = new KeyPairGeneratorSpi();
    GOST3410ParameterSpec paramSpec = new GOST3410ParameterSpec("Tc26-Gost-3410-12-256-paramSetA");

    try {
      ECGOST3410.initialize(paramSpec, SecureRandom.getInstanceStrong());
    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException ignored) {
    }

    KeyPair pair = ECGOST3410.generateKeyPair();
    BCECGOST3410PrivateKey privateKey = (BCECGOST3410PrivateKey) pair.getPrivate();
    BCECGOST3410PublicKey publicKey = (BCECGOST3410PublicKey) pair.getPublic();

    return new ECKeyPair(
            new DjbECPublicKey(publicKey.getQ().getEncoded(false)),
            new DjbECPrivateKey(privateKey.getS().toByteArray())
    );
  }

  public static ECPublicKey decodePoint(byte[] bytes, int offset) {
    return new DjbECPublicKey(bytes);
  }

  public static ECPrivateKey decodePrivatePoint(byte[] bytes) {
    return new DjbECPrivateKey(bytes);
  }

  public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
          throws InvalidKeyException {
    if (publicKey == null) {
      throw new InvalidKeyException("public value is null");
    }

    if (privateKey == null) {
      throw new InvalidKeyException("private value is null");
    }

    ECVKOAgreement vkoAgreement = new ECVKOAgreement(new GOST3411_2012_256Digest());

    ECDomainParameters ecParams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");
    ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(
            new BigInteger(privateKey.serialize()),
            ecParams
    );
    ParametersWithUKM UKMParams = new ParametersWithUKM(
            privateKeyParams,
            BigInteger.valueOf(Long.MAX_VALUE).toByteArray()
    );
    vkoAgreement.init(UKMParams);
    ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            ecParams.getCurve().decodePoint(publicKey.serialize()),
            ecParams
    );
    return vkoAgreement.calculateAgreement(pubKey);
  }

  public static boolean verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
          throws InvalidKeyException {
    ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
    GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();

    ECDomainParameters ecParams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");
    ECPublicKeyParameters privateKeyParams = new ECPublicKeyParameters(
            ecParams.getCurve().decodePoint(signingKey.serialize()),
            ecParams
    );
    signer.init(false, privateKeyParams);

    BigInteger r = new BigInteger(Arrays.copyOfRange(signature, 0, 32));
    BigInteger s = new BigInteger(Arrays.copyOfRange(signature, 32, signature.length));

    byte[] messageHash = new byte[256];
    digest.update(message, 0, message.length);
    digest.doFinal(messageHash, 0);

    return signer.verifySignature(messageHash, r, s);
  }

  public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
          throws InvalidKeyException {

    ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
    GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();

    ECDomainParameters ecParams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");
    ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(
            new BigInteger(signingKey.serialize()),
            ecParams
    );
    signer.init(true, privateKeyParams);
    byte[] messageHash = new byte[256];
    digest.update(message, 0, message.length);
    digest.doFinal(messageHash, 0);

    BigInteger[] sign = signer.generateSignature(messageHash);
    return Arrays.stream(sign).map(BigInteger::toByteArray).reduce(new byte[0], ByteUtil::combine);
  }

  public static byte[] calculateVrfSignature(ECPrivateKey signingKey, byte[] message)
          throws InvalidKeyException {
    ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
    GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();

    ECDomainParameters ecParams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");
    ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(
            new BigInteger(signingKey.serialize()),
            ecParams
    );
    signer.init(true, privateKeyParams);
    byte[] messageHash = new byte[256];
    digest.update(message, 0, message.length);
    digest.doFinal(messageHash, 0);

    BigInteger[] sign = signer.generateSignature(messageHash);
    return Arrays.stream(sign).map(BigInteger::toByteArray).reduce(new byte[0], ByteUtil::combine);
  }

  public static byte[] verifyVrfSignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException, VrfSignatureVerificationFailedException {
    ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
    GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();

    ECDomainParameters ecParams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");
    ECPublicKeyParameters privateKeyParams = new ECPublicKeyParameters(
            ecParams.getCurve().decodePoint(signingKey.serialize()),
            ecParams
    );
    signer.init(false, privateKeyParams);

    BigInteger r = new BigInteger(Arrays.copyOfRange(signature, 0, 32));
    BigInteger s = new BigInteger(Arrays.copyOfRange(signature, 32, signature.length));

    byte[] messageHash = new byte[256];
    digest.update(message, 0, message.length);
    digest.doFinal(messageHash, 0);

    boolean isCorrect = signer.verifySignature(messageHash, r, s);

    if (!isCorrect) throw new RuntimeException("Illegal signature!");

    byte[] hashSignature = new byte[256];
    digest.update(signature, 0, signature.length);
    digest.doFinal(hashSignature, 0);

    return hashSignature;
  }

}
