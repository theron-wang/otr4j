/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import net.java.otr4j.crypto.DSAKeyPair.DSASignature;
import net.java.otr4j.crypto.DSAKeyPair.EncodedDSAKeyPair;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.DSAKeyPair.createDSAPublicKey;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.crypto.DSAKeyPair.restoreDSAKeyPair;
import static net.java.otr4j.crypto.DSAKeyPair.verifySignature;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

@SuppressWarnings("ConstantConditions")
public final class DSAKeyPairTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DSAKeyPair DSA_KEYPAIR = generateDSAKeyPair();

    @Test
    public void testGenerateDSAKeyPair() {
        final DSAKeyPair keypair = generateDSAKeyPair();
        assertNotNull(keypair);
        assertNotNull(keypair.getPublic());
    }

    @Test(expected = NullPointerException.class)
    public void testSignRSNullMessage() {
        DSA_KEYPAIR.signRS(null);
    }

    @Test
    public void testSignRS() throws OtrCryptoException {
        final byte[] m = "hello".getBytes(UTF_8);
        final DSASignature sig = DSA_KEYPAIR.signRS(m);
        verifySignature(m, DSA_KEYPAIR.getPublic(), sig.r, sig.s);
    }

    @Test(expected = NullPointerException.class)
    public void testSignNullMessage() {
        final DSAKeyPair keypair = generateDSAKeyPair();
        keypair.sign(null);
    }

    @Test
    public void testSignMessage() throws OtrCryptoException {
        final byte[] data = randomBytes(RANDOM, new byte[RANDOM.nextInt(1000)]);
        final DSAKeyPair keypair = generateDSAKeyPair();
        final byte[] signature = keypair.sign(data);
        DSAKeyPair.verifySignature(data, keypair.getPublic(), signature);
    }

    @Test
    public void testSignRSEmptyMessage() throws OtrCryptoException {
        assumeTrue("This test can only be successful without assertions, due to safety checks.",
                !OtrCryptoEngine.class.desiredAssertionStatus());
        final byte[] m = new byte[0];
        final DSASignature sig = DSA_KEYPAIR.signRS(m);
        verifySignature(m, DSA_KEYPAIR.getPublic(), sig.r, sig.s);
    }

    @Test
    public void testGenerateDSAKeyPairDifferentKeyPairs() {
        final DSAKeyPair keypair1 = generateDSAKeyPair();
        final DSAKeyPair keypair2 = generateDSAKeyPair();
        final DSAKeyPair keypair3 = generateDSAKeyPair();
        assertNotEquals(keypair1.getPublic().getY(), keypair2.getPublic().getY());
        assertNotEquals(keypair1.getPublic().getY(), keypair3.getPublic().getY());
        assertNotEquals(keypair2.getPublic().getY(), keypair3.getPublic().getY());
        assertNotEquals(keypair1, keypair2);
        assertNotEquals(keypair1, keypair3);
        assertNotEquals(keypair2, keypair3);
    }

    @Test
    public void testRecreateDSAPublicKey() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(keypair.getPublic().getY(), params.getP(), params.getQ(), params.getG());
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = RuntimeException.class)
    public void testRecreateDSAPublicKeyNullY() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(null, params.getP(), params.getQ(), params.getG());
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = RuntimeException.class)
    public void testRecreateDSAPublicKeyNullP() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(keypair.getPublic().getY(), null, params.getQ(), params.getG());
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = RuntimeException.class)
    public void testRecreateDSAPublicKeyNullQ() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(keypair.getPublic().getY(), params.getP(), null, params.getG());
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = RuntimeException.class)
    public void testRecreateDSAPublicKeyNullG() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(keypair.getPublic().getY(), params.getP(), params.getQ(), null);
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = NullPointerException.class)
    public void testRestoreNullPrivateKey() throws OtrCryptoException {
        restoreDSAKeyPair(null, new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testRestoreNullPublicKey() throws OtrCryptoException {
        restoreDSAKeyPair(new byte[0], null);
    }

    @Test
    public void testRestoreGeneratedDSAKeyPair() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final EncodedDSAKeyPair encoded = keypair.encodeDSAKeyPair();
        final DSAKeyPair restored = restoreDSAKeyPair(encoded.encodedPrivateKey, encoded.encodedPublicKey);
        assertEquals(keypair, restored);
    }

    @Test
    public void testRestoreAndReencodePersistedDSAKeyPair() throws OtrCryptoException {
        final byte[] encodedPublicKey = new byte[]{48, -126, 1, -73, 48, -126, 1, 44, 6, 7, 42, -122, 72, -50, 56, 4, 1, 48, -126, 1, 31, 2, -127, -127, 0, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60, -17, 68, 0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70, 48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102, 96, -73, 107, -103, 80, -91, -92, -97, -97, -24, 4, 123, 16, 34, -62, 79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21, 15, 4, -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43, 97, -41, 42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57, 2, 21, 0, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11, 2, -127, -127, 0, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87, -71, 121, -108, -81, -69, -6, 58, -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127, -128, -76, 73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117, 84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5, 98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6, -110, -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42, 3, -127, -124, 0, 2, -127, -128, 105, -124, -65, -96, -109, 27, 45, -10, 77, 62, 127, 34, -15, -116, -87, -69, 70, -121, -126, 106, -115, -82, -122, -106, 34, 26, -29, 35, -31, -84, 62, -29, 127, 125, 45, 39, -109, 95, -48, -118, -20, 38, -55, -14, 6, -60, -35, -97, -6, 26, -3, -65, 122, -104, 48, -6, -50, 87, -39, 25, -93, 9, 22, 118, 106, 58, -105, 54, -26, -67, -78, 46, 28, 70, 124, 38, 11, 30, 67, -3, -4, 93, 86, 42, -16, 119, 47, -7, -113, 65, -101, -8, -126, 23, 54, -70, 83, -61, -93, 82, -61, -60, -1, 53, -96, -126, -49, 83, 75, 27, -28, 102, 102, -32, -74, 76, 80, 95, -44, 62, -32, 74, -37, -7, 66, -78, -14, -32};
        final byte[] encodedPrivateKey = new byte[]{48, -126, 1, 76, 2, 1, 0, 48, -126, 1, 44, 6, 7, 42, -122, 72, -50, 56, 4, 1, 48, -126, 1, 31, 2, -127, -127, 0, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60, -17, 68, 0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70, 48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102, 96, -73, 107, -103, 80, -91, -92, -97, -97, -24, 4, 123, 16, 34, -62, 79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21, 15, 4, -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43, 97, -41, 42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57, 2, 21, 0, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11, 2, -127, -127, 0, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87, -71, 121, -108, -81, -69, -6, 58, -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127, -128, -76, 73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117, 84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5, 98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6, -110, -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42, 4, 23, 2, 21, 0, -107, 111, 97, -13, 17, -7, 37, -70, -101, 96, -109, 85, -101, 69, -77, -105, 28, 12, -119, -70};
        final DSAKeyPair restored = restoreDSAKeyPair(encodedPrivateKey, encodedPublicKey);
        final EncodedDSAKeyPair reencoded = restored.encodeDSAKeyPair();
        assertArrayEquals(encodedPublicKey, reencoded.encodedPublicKey);
        assertArrayEquals(encodedPrivateKey, reencoded.encodedPrivateKey);
    }
}