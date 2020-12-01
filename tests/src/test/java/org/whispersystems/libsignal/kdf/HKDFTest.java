package org.whispersystems.libsignal.kdf;

import junit.framework.TestCase;

import java.util.Arrays;

public class HKDFTest extends TestCase {

  public void testVectorV3() {
    byte[] ikm = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b};

    byte[] salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c};

    byte[] info = {(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4,
            (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9};

    byte[] okm = {
            53, -8, -8, 3, 122, -83, -9,
            -81, 62, 79, -57, -68, -117,
            -109, -87, 39, -42, -123, -44,
            47, 102, 40, -7, -26, 35, -56,
            94, 25, 112, 9, 105, 46, -82,
            -79, 11, 37, 38, 113, 42, 123,
            73, -73
    };

    byte[] actualOutput = HKDF.createFor(3).deriveSecrets(ikm, salt, info, 42);
    byte[] actualOutput2 = HKDF.createFor(3).deriveSecrets(ikm, salt, info, 42);

    assertTrue(Arrays.equals(actualOutput2, actualOutput));
    assertTrue(actualOutput.length == 42);

    System.out.println("This is test result: " + Arrays.toString(actualOutput));

    assertTrue(Arrays.equals(okm, actualOutput));
  }

  public void testVectorLongV3() {
    byte[] ikm  = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                   (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09,
                   (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
                   (byte) 0x0f, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                   (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18,
                   (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
                   (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22,
                   (byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27,
                   (byte) 0x28, (byte) 0x29, (byte) 0x2a, (byte) 0x2b, (byte) 0x2c,
                   (byte) 0x2d, (byte) 0x2e, (byte) 0x2f, (byte) 0x30, (byte) 0x31,
                   (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36,
                   (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x3a, (byte) 0x3b,
                   (byte) 0x3c, (byte) 0x3d, (byte) 0x3e, (byte) 0x3f, (byte) 0x40,
                   (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45,
                   (byte) 0x46, (byte) 0x47, (byte) 0x48, (byte) 0x49, (byte) 0x4a,
                   (byte) 0x4b, (byte) 0x4c, (byte) 0x4d, (byte) 0x4e, (byte) 0x4f};

    byte[] salt = {(byte) 0x60, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64,
                   (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x69,
                   (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e,
                   (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x72, (byte) 0x73,
                   (byte) 0x74, (byte) 0x75, (byte) 0x76, (byte) 0x77, (byte) 0x78,
                   (byte) 0x79, (byte) 0x7a, (byte) 0x7b, (byte) 0x7c, (byte) 0x7d,
                   (byte) 0x7e, (byte) 0x7f, (byte) 0x80, (byte) 0x81, (byte) 0x82,
                   (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
                   (byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b, (byte) 0x8c,
                   (byte) 0x8d, (byte) 0x8e, (byte) 0x8f, (byte) 0x90, (byte) 0x91,
                   (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96,
                   (byte) 0x97, (byte) 0x98, (byte) 0x99, (byte) 0x9a, (byte) 0x9b,
                   (byte) 0x9c, (byte) 0x9d, (byte) 0x9e, (byte) 0x9f, (byte) 0xa0,
                   (byte) 0xa1, (byte) 0xa2, (byte) 0xa3, (byte) 0xa4, (byte) 0xa5,
                   (byte) 0xa6, (byte) 0xa7, (byte) 0xa8, (byte) 0xa9, (byte) 0xaa,
                   (byte) 0xab, (byte) 0xac, (byte) 0xad, (byte) 0xae, (byte) 0xaf};

    byte[] info = {(byte) 0xb0, (byte) 0xb1, (byte) 0xb2, (byte) 0xb3, (byte) 0xb4,
                   (byte) 0xb5, (byte) 0xb6, (byte) 0xb7, (byte) 0xb8, (byte) 0xb9,
                   (byte) 0xba, (byte) 0xbb, (byte) 0xbc, (byte) 0xbd, (byte) 0xbe,
                   (byte) 0xbf, (byte) 0xc0, (byte) 0xc1, (byte) 0xc2, (byte) 0xc3,
                   (byte) 0xc4, (byte) 0xc5, (byte) 0xc6, (byte) 0xc7, (byte) 0xc8,
                   (byte) 0xc9, (byte) 0xca, (byte) 0xcb, (byte) 0xcc, (byte) 0xcd,
                   (byte) 0xce, (byte) 0xcf, (byte) 0xd0, (byte) 0xd1, (byte) 0xd2,
            (byte) 0xd3, (byte) 0xd4, (byte) 0xd5, (byte) 0xd6, (byte) 0xd7,
            (byte) 0xd8, (byte) 0xd9, (byte) 0xda, (byte) 0xdb, (byte) 0xdc,
            (byte) 0xdd, (byte) 0xde, (byte) 0xdf, (byte) 0xe0, (byte) 0xe1,
            (byte) 0xe2, (byte) 0xe3, (byte) 0xe4, (byte) 0xe5, (byte) 0xe6,
            (byte) 0xe7, (byte) 0xe8, (byte) 0xe9, (byte) 0xea, (byte) 0xeb,
            (byte) 0xec, (byte) 0xed, (byte) 0xee, (byte) 0xef, (byte) 0xf0,
            (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5,
            (byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9, (byte) 0xfa,
            (byte) 0xfb, (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};

    byte[] okm = {40, -116, 39, -1, -38, -10, 75, -24, 36, -34, -124, -109, 72, -99, 3, 18, 40, 7,
            -23, 36, -86, 106, 9, 39, 1, 22, -99, 47, 102, 56, -55, -43, -62, -65, 9,
            -37, -97, -66, 11, 50, -120, 89, 123, 103, 29, -81, 23, -19, 62, 125,
            -91, -119, -33, 105, -52, 29, -36, -40, 38, 44, 28, 107, -31, 75,
            -64, -72, 92, 76, 43, 36, -74, -40, -76, 56, 24, -95, -91,
            -80, 103, 83, -81, 114};

    byte[] actualOutput = HKDF.createFor(3).deriveSecrets(ikm, salt, info, 82);
    byte[] actualOutput2 = HKDF.createFor(3).deriveSecrets(ikm, salt, info, 82);

    System.out.println("This is test result: " + Arrays.toString(actualOutput) + " size is: " + actualOutput.length);
    assertTrue(Arrays.equals(actualOutput2, actualOutput));
    assertTrue(Arrays.equals(okm, actualOutput));
    assertTrue(actualOutput.length == 82);
  }

  public void testVectorV2() {
    byte[] ikm = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                  0x0b, 0x0b};

    byte[] salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                   0x0a, 0x0b, 0x0c};

    byte[] info = {(byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3, (byte)0xf4,
                   (byte)0xf5, (byte)0xf6, (byte)0xf7, (byte)0xf8, (byte)0xf9};

    byte[] okm = {-52, -56, -25, 28, 17, 18, -27, 79, -121, 35, -70, 39, 78, -111, 80, 119, 4, 66, -121, 98, -92, -117, 36, -40, -95, -104, 51, -99, 29, -4, -22, -94, -10, 18, 63, -91, 9, -17, 57, 10, 127, 71, 71, -90, -65, -82, 20, -43, 5, -56, -56, -94, -57, -48, -47, -114, 63, 0, -67, 75, -54, 73, -48, -92};

    byte[] actualOutput = HKDF.createFor(2).deriveSecrets(ikm, salt, info, 64);
    byte[] actualOutput2 = HKDF.createFor(2).deriveSecrets(ikm, salt, info, 64);

    assertTrue(Arrays.equals(actualOutput2, actualOutput));
    System.out.println("This is test result: " + Arrays.toString(actualOutput) + " size is: " + actualOutput.length);

    assertTrue(Arrays.equals(okm, actualOutput));
    assertTrue(actualOutput.length == 64);
  }
}
