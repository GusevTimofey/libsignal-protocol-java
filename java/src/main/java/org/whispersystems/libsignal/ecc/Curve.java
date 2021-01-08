/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;

import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.ECVKOAgreement;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.generators.GOST3410KeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.KeyAgreementSpi;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.curve25519.VrfSignatureVerificationFailedException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.ByteUtil;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA;
import static org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;
import static org.whispersystems.curve25519.Curve25519.BEST;

public class Curve {

  public  static final int DJB_TYPE   = 0x05;

  public static boolean isNative() {
    return Curve25519.getInstance(BEST).isNative();
  }

  public static ECKeyPair generateKeyPair() {
    KeyPairGeneratorSpi gen = new KeyPairGeneratorSpi();
    try {
      gen.initialize(new GOST3410ParameterSpec("Tc26-Gost-3410-12-256-paramSetA"), SecureRandom.getInstanceStrong());
    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    KeyPair pair = gen.generateKeyPair();
    BCECGOST3410PrivateKey pk = (BCECGOST3410PrivateKey)pair.getPrivate();
    BCECGOST3410PublicKey puk = (BCECGOST3410PublicKey)pair.getPublic();
    System.out.println("pk.getS()" + pk.getS());
    System.out.println("pk.getS().toByteArray()" + Arrays.toString(pk.getS().toByteArray()));
    System.out.println("pk.getQ()" + new BigInteger(puk.getQ().getEncoded(false)));
    System.out.println("pk.getQ().toByteArray()" + Arrays.toString(puk.getQ().getEncoded(false)));

    return new ECKeyPair(new DjbECPublicKey(puk.getQ().getEncoded(false)),
            new DjbECPrivateKey(pk.getS().toByteArray()));
  }

  public static ECPublicKey decodePoint(byte[] bytes, int offset)
      throws InvalidKeyException
  {
    if (bytes == null || bytes.length - offset < 1) {
      throw new InvalidKeyException("No key type identifier");
    }

    return new DjbECPublicKey(bytes);
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

    ECVKOAgreement vko = new ECVKOAgreement(new GOST3411_2012_256Digest());
    ECDomainParameters ecparams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");
    ECPrivateKeyParameters pk = new ECPrivateKeyParameters(new BigInteger(privateKey.serialize()), ecparams);
    System.out.println("calculateAgreement: " + Arrays.toString(publicKey.serialize()));
    ParametersWithUKM parms = new ParametersWithUKM(pk, BigInteger.valueOf(Long.MAX_VALUE).toByteArray());
    vko.init(parms);
    ECPublicKeyParameters pubKey = new ECPublicKeyParameters(ecparams.getCurve().decodePoint(publicKey.serialize()), ecparams);
    byte[] res = vko.calculateAgreement(pubKey);
    return res;
  }

  public static boolean verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException
  {
    ECDomainParameters ecparams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");
    System.out.println("verifySignature. Key is " + Arrays.toString(signingKey.serialize()));
    System.out.println("pub key:" + new BigInteger(signingKey.serialize()));
    ECPublicKeyParameters pk = new ECPublicKeyParameters(ecparams.getCurve().decodePoint(signingKey.serialize()), ecparams);
    ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
    signer.init(false, pk);

    byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
    byte[] sBytes = Arrays.copyOfRange(signature, 32, signature.length);

    System.out.println("rBytes " + Arrays.toString(rBytes));
    System.out.println("sBytes " + Arrays.toString(sBytes));

    BigInteger r = new BigInteger(rBytes);
    BigInteger s = new BigInteger(sBytes);

    GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();
    byte[] messageCorrect = new byte[256];
    digest.update(message, 0, message.length);
    digest.doFinal(messageCorrect, 0);

    boolean isCorrect = signer.verifySignature(messageCorrect, r, s);

    return isCorrect;
  }

  public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    ECDomainParameters ecparams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");

    System.out.println("calculateSignature. signingKey Key length is " + signingKey.serialize().length + " " + Arrays.toString(signingKey.serialize()));
    ECPrivateKeyParameters pk = new ECPrivateKeyParameters(new BigInteger(signingKey.serialize()), ecparams);
    ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
    signer.init(true, pk);
    GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();
    byte[] messageCorrect = new byte[256];
    digest.update(message, 0, message.length);
    digest.doFinal(messageCorrect, 0);

    BigInteger[] digestFinal = signer.generateSignature(messageCorrect);
    System.out.println("digestFinal do:" + Arrays.toString(digestFinal));
    Arrays.stream(digestFinal).forEach(a -> System.out.println(Arrays.toString(a.toByteArray()) + " length is:" + a.toByteArray().length));
    int size = Arrays.stream(digestFinal).map(b -> b.toByteArray().length).reduce(0, Integer::sum);
    byte[] res = Arrays.stream(digestFinal).map(BigInteger::toByteArray).reduce(new byte[0], ByteUtil::combine);
    System.out.println(Arrays.toString(res) + " size " + size + " ... " + res.length);
    return res;
  }

  public static byte[] calculateVrfSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    ECDomainParameters ecparams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");

    System.out.println("calculateSignature. signingKey Key length is " + signingKey.serialize().length + " " + Arrays.toString(signingKey.serialize()));
    ECPrivateKeyParameters pk = new ECPrivateKeyParameters(new BigInteger(signingKey.serialize()), ecparams);
    ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
    signer.init(true, pk);
    GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();
    byte[] messageCorrect = new byte[256];
    digest.update(message, 0, message.length);
    digest.doFinal(messageCorrect, 0);

    BigInteger[] digestFinal = signer.generateSignature(messageCorrect);
    System.out.println("digestFinal do:" + Arrays.toString(digestFinal));
    Arrays.stream(digestFinal).forEach(a -> System.out.println(Arrays.toString(a.toByteArray()) + " length is:" + a.toByteArray().length));
    byte[] res = Arrays.stream(digestFinal).map(BigInteger::toByteArray).reduce(new byte[0], ByteUtil::combine);
    System.out.println(Arrays.toString(res) + " size " + " ... " + res.length);
    return res;
  }

  public static byte[] verifyVrfSignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException, VrfSignatureVerificationFailedException
  {
    ECDomainParameters ecparams = ECGOST3410NamedCurves.getByName("Tc26-Gost-3410-12-256-paramSetA");
    System.out.println("verifySignature. Key is " + Arrays.toString(signingKey.serialize()));
    System.out.println("pub key:" + new BigInteger(signingKey.serialize()));
    ECPublicKeyParameters pk = new ECPublicKeyParameters(ecparams.getCurve().decodePoint(signingKey.serialize()), ecparams);
    ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
    signer.init(false, pk);

    byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
    byte[] sBytes = Arrays.copyOfRange(signature, 32, signature.length);

    System.out.println("rBytes " + Arrays.toString(rBytes));
    System.out.println("sBytes " + Arrays.toString(sBytes));

    BigInteger r = new BigInteger(rBytes);
    BigInteger s = new BigInteger(sBytes);

    GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();
    byte[] messageCorrect = new byte[256];
    digest.update(message, 0, message.length);
    digest.doFinal(messageCorrect, 0);

    boolean isCorrect = signer.verifySignature(messageCorrect, r, s);

    if (!isCorrect) throw new RuntimeException("Illegal signature!");

    byte[] resCorrect = new byte[256];
    digest.update(signature, 0, signature.length);
    digest.doFinal(resCorrect, 0);

    return resCorrect;
  }

}
