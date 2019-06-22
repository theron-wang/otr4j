/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FINGERPRINT;
import static net.java.otr4j.crypto.OtrCryptoEngine4.decodePoint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.decrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine4.deriveExtraSymmetricKey;
import static net.java.otr4j.crypto.OtrCryptoEngine4.encrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.crypto.OtrCryptoEngine4.verifyEdDSAPublicKey;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Ed448.identity;
import static net.java.otr4j.crypto.ed448.PointTestUtils.createPoint;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

@SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
public class OtrCryptoEngine4Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BigInteger MINUSONE = BigInteger.valueOf(-1L);

    private final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
    private final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
    private final ECDHKeyPair ephemeralKeyPair = ECDHKeyPair.generate(RANDOM);

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullPublicKey() {
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        fingerprint(null, forgingKey);
    }

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullForgingKey() {
        final Point publicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        fingerprint(publicKey, null);
    }

    @Test
    public void testFingerprint() {
        final byte[] expected = new byte[] {-99, 52, -14, -68, -84, -20, 32, -108, 38, 62, 58, 115, 64, -115, -97, 114, 20, 125, 59, -105, 66, 29, -128, -127, 57, 119, 39, -124, 37, 125, 49, -104, 17, 102, 46, 117, -54, 127, 107, 23, 87, 105, 38, 81, -13, -55, 56, 88, -76, 33, 66, -35, -81, -66, -99, -31};
        final byte[] dst = fingerprint(basePoint(), basePoint());
        assertArrayEquals(expected, dst);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullDestination() {
        final byte[] input = "someinput".getBytes(US_ASCII);
        kdf(null, 0, FINGERPRINT, 32, input);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullKDFUsage() {
        final byte[] dst = new byte[100];
        kdf(dst, 0, null, 32, new byte[] {(byte) 0xff});
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullInput() {
        final byte[] dst = new byte[100];
        kdf(dst, 0, FINGERPRINT, 32, (byte[]) null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        kdf(new byte[1], 0, FINGERPRINT, 32, input);
    }

    @Test
    public void testKdf1DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {51, 79, -93, 96, 82, -80, -50, 81, 65, 106, -39, -43, 79, 58, 69, -26, -73, -52, -110, -48, -110, -66, -23, -26, 76, -43, 65, 120, 52, -65, -71, -50, 0};
        final byte[] dst = new byte[32 + 1];
        kdf(dst, 0, FINGERPRINT, 32, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {0, 51, 79, -93, 96, 82, -80, -50, 81, 65, 106, -39, -43, 79, 58, 69, -26, -73, -52, -110, -48, -110, -66, -23, -26, 76, -43, 65, 120, 52, -65, -71, -50};
        final byte[] dst = new byte[32 + 1];
        kdf(dst, 1, FINGERPRINT, 32, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[] {51, 79, -93, 96, 82, -80, -50, 81, 65, 106, -39, -43, 79, 58, 69, -26, -73, -52, -110, -48, -110, -66, -23, -26, 76, -43, 65, 120, 52, -65, -71, -50};
        final byte[] dst = new byte[32];
        kdf(dst, 0, FINGERPRINT, 32, input);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKdf1NegativeOutputSize() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[32];
        kdf(dst, 0, FINGERPRINT, -1, input);
    }

    @Test
    public void testKdf1ReturnValue() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] expected = new byte[32];
        kdf(expected, 0, FINGERPRINT, 32, input);
        assertArrayEquals(expected, kdf(FINGERPRINT, 32, input));
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1ReturnValueNullUsageID() {
        kdf(null, 32, new byte[] {1});
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1ReturnValueNullInput() {
        kdf(FINGERPRINT, 32, (byte[]) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKdf1ReturnValueBadOutputSize() {
        kdf(FINGERPRINT, -1, "helloworld".getBytes(US_ASCII));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(US_ASCII);
        final byte[] dst = new byte[32];
        kdf(dst, 1, FINGERPRINT, 32, input);
    }

    @Test(expected = NullPointerException.class)
    public void testHashToScalarNullKDFUsage() {
        hashToScalar(null, new byte[] {1});
    }

    @Test(expected = NullPointerException.class)
    public void testHashToScalarNullBytes() {
        hashToScalar(FINGERPRINT, (byte[]) null);
    }

    @Test
    public void testHashToScalar() {
        final Scalar expected = decodeScalar(new byte[] {105, 16, -83, 85, -9, -62, -46, -92, 7, -23, 67, 50, -59, 94, -15, 91, -59, -120, -64, -43, -77, 27, 44, 3, -94, -23, 33, 64, 125, -65, -71, -50, -103, -100, 31, 100, -19, 85, 74, -13, 2, 94, -128, 70, -12, -52, 46, 126, 49, 105, 43, -65, 56, -50, -41, 33, 0});
        final Scalar actual = hashToScalar(FINGERPRINT, "helloworld".getBytes(US_ASCII));
        assertEquals(expected, actual);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateEdDSAKeyPairNull() {
        EdDSAKeyPair.generate(null);
    }

    @Test
    public void testGenerateEdDSAKeyPair() {
        assertNotNull(EdDSAKeyPair.generate(RANDOM));
    }

    @Ignore("This test is most likely correct and verification is missing logic. Disabled for now for further research.")
    @Test(expected = OtrCryptoException.class)
    public void testVerifyEdDSAPublicKeyOne() throws OtrCryptoException {
        verifyEdDSAPublicKey(identity());
    }

    @Test
    public void testVerifyEdDSAPublicKeyLegit() throws OtrCryptoException {
        EdDSAKeyPair keypair = EdDSAKeyPair.generate(RANDOM);
        verifyEdDSAPublicKey(keypair.getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullKey() {
        encrypt(null, new byte[1]);
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNullMessage() {
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        encrypt(key, null);
    }

    @Test
    public void testEncryptMessage() {
        final byte[] message = "hello world".getBytes(UTF_8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] ciphertext = encrypt(key, message);
        assertNotNull(ciphertext);
        assertFalse(Arrays.equals(message, ciphertext));
    }

    @Test
    public void testEncryptionAndDecryption() {
        final byte[] message = "hello, do the salsa".getBytes(UTF_8);
        final byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        final byte[] result = decrypt(key, encrypt(key, message));
        assertArrayEquals(message, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptInvalidKeySize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF_8);
        final byte[] key = new byte[31];
        RANDOM.nextBytes(key);
        encrypt(key, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptInvalidKeySize() {
        final byte[] message = "hello, do the salsa".getBytes(UTF_8);
        final byte[] key = new byte[31];
        RANDOM.nextBytes(key);
        decrypt(key, message);
    }

    @Test(expected = NullPointerException.class)
    public void testDecodePointNull() throws OtrCryptoException {
        decodePoint(null);
    }

    @Test(expected = OtrCryptoException.class)
    public void testDecodePointInvalidLengthLow() throws OtrCryptoException {
        decodePoint(new byte[56]);
    }

    @Test(expected = OtrCryptoException.class)
    public void testDecodePointInvalidLengthHigh() throws OtrCryptoException {
        decodePoint(new byte[58]);
    }

    @Test
    public void testDecodePoint() throws OtrCryptoException {
        final Point point = decodePoint(ephemeralKeyPair.getPublicKey().encode());
        assertEquals(ephemeralKeyPair.getPublicKey(), point);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullRandom() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(null, longTermKeyPairA, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullKeypair() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, null, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullA1() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, longTermKeyPairA, null, longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullA2() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullA3() {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), null, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRingSignIllegalA1() {
        final byte[] message = "hello world".getBytes(UTF_8);
        final Point illegal = createPoint(MINUSONE, MINUSONE);
        ringSign(RANDOM, longTermKeyPairB, illegal, longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRingSignIllegalA2() {
        final byte[] message = "hello world".getBytes(UTF_8);
        final Point illegal = createPoint(MINUSONE, MINUSONE);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(), illegal, ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRingSignIllegalA3() {
        final byte[] message = "hello world".getBytes(UTF_8);
        final Point illegal = createPoint(MINUSONE, MINUSONE);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), illegal, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingSignNullMessage() {
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRingSignKeyPairNotPresentInPublicKeys() {
        final EdDSAKeyPair longTermKeyPairA2 = EdDSAKeyPair.generate(RANDOM);
        final byte[] message = "hello world".getBytes(UTF_8);
        ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(), longTermKeyPairA2.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullA1() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(null, longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), sigma, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullA2() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(longTermKeyPairA.getPublicKey(), null, ephemeralKeyPair.getPublicKey(), sigma, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullA3() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), null, sigma, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullSigma() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(),
                null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testRingVerifyNullMessage() throws OtrCryptoException {
        final EdDSAKeyPair longTermKeyPairA = EdDSAKeyPair.generate(RANDOM);
        final EdDSAKeyPair longTermKeyPairB = EdDSAKeyPair.generate(RANDOM);
        final byte[] message = "hello world".getBytes(UTF_8);
        final Point ephemeral = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeral, message);
        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeral, sigma, null);
    }

    @Test
    public void testRingSigningWithA1() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(longTermKeyPairA.getPublicKey(), longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(),
                sigma, message);
    }

    @Test
    public void testRingSigningWithA2() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(),
                longTermKeyPairA.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        ringVerify(longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeralKeyPair.getPublicKey(),
                sigma, message);
    }

    @Test
    public void testRingSigningWithA3() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairB.getPublicKey(),
                ephemeralKeyPair.getPublicKey(), longTermKeyPairA.getPublicKey(), message);
        ringVerify(longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), longTermKeyPairA.getPublicKey(),
                sigma, message);
    }

    @Test(expected = OtrCryptoException.class)
    public void testRingSignDifferentMessage() throws OtrCryptoException {
        final byte[] message = "hello world".getBytes(UTF_8);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, longTermKeyPairA, longTermKeyPairA.getPublicKey(),
                longTermKeyPairB.getPublicKey(), ephemeralKeyPair.getPublicKey(), message);
        final byte[] wrongMessage = "hello World".getBytes(UTF_8);
        ringVerify(longTermKeyPairB.getPublicKey(), longTermKeyPairA.getPublicKey(), ephemeralKeyPair.getPublicKey(),
                sigma, wrongMessage);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateRandomValueInZqNullSecureRandom() {
        generateRandomValueInZq(null);
    }

    @Ignore("There is a FIXME to investigate whether this is necessary. I believe it isn't.")
    @Test
    public void testGenerateRandomValueInZq() {
        final Scalar value = generateRandomValueInZq(RANDOM);
        final byte[] bytes = value.encode();
        assertEquals(0, bytes[0] & 0b00000011);
        assertEquals(0b10000000, bytes[55] & 0b10000000);
        assertEquals(0, bytes[56]);
    }

    @Test
    public void testGenerateRandomValueInZqNoThreeAreTheSame() {
        final Scalar v1 = generateRandomValueInZq(RANDOM);
        final Scalar v2 = generateRandomValueInZq(RANDOM);
        final Scalar v3 = generateRandomValueInZq(RANDOM);
        assertNotEquals(v1, v2);
        assertNotEquals(v2, v3);
        assertNotEquals(v1, v3);
    }

    @Test
    public void testDeriveExtraSymmetricKeys() {
        final byte[] baseKey = randomBytes(RANDOM, new byte[64]);
        final byte[] context = randomBytes(RANDOM, new byte[4]);
        final byte[] derived = deriveExtraSymmetricKey(1, context, baseKey);
        assertNotNull(derived);
        assertFalse(allZeroBytes(derived));
        assertFalse(Arrays.equals(baseKey, derived));
    }

    @Test
    public void testDeriveExtraSymmetricKeysRepeatedly() {
        final byte[] baseKey = randomBytes(RANDOM, new byte[64]);
        final byte[] context = randomBytes(RANDOM, new byte[4]);
        final byte[] derived1 = deriveExtraSymmetricKey(1, context, baseKey);
        final byte[] derived2 = deriveExtraSymmetricKey(1, context, baseKey);
        final byte[] derived3 = deriveExtraSymmetricKey(1, context, baseKey);
        assertArrayEquals(derived1, derived2);
        assertArrayEquals(derived2, derived3);
    }

    @Test
    public void testDeriveExtraSymmetricKeysIncrementally() {
        final byte[] baseKey = randomBytes(RANDOM, new byte[64]);
        final byte[] context = randomBytes(RANDOM, new byte[4]);
        final byte[] derived1 = deriveExtraSymmetricKey(1, context, baseKey);
        final byte[] derived2 = deriveExtraSymmetricKey(2, context, baseKey);
        final byte[] derived3 = deriveExtraSymmetricKey(3, context, baseKey);
        assertFalse(Arrays.equals(derived1, derived2));
        assertFalse(Arrays.equals(derived2, derived3));
    }

    @Test(expected = NullPointerException.class)
    public void testDeriveExtraSymmetricKeysNullContext() {
        final byte[] baseKey = randomBytes(RANDOM, new byte[64]);
        deriveExtraSymmetricKey(1, null, baseKey);
    }

    @Test(expected = NullPointerException.class)
    public void testDeriveExtraSymmetricKeysNullBaseKey() {
        final byte[] context = randomBytes(RANDOM, new byte[4]);
        deriveExtraSymmetricKey(1, context, null);
    }
}
