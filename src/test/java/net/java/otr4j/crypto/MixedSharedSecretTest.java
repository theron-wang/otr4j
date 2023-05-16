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
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.bouncycastle.util.Arrays.fill;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.internal.util.reflection.Whitebox.getInternalState;

/**
 * The MixedSharedSecret tests currently do not perform a test that binary-exactly verifies that the right values are
 * produced. For now we verify immutability of values and that values change after rotation.
 */
@SuppressWarnings({"ConstantConditions", "resource"})
public class MixedSharedSecretTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();

    private static final Point theirNextECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();

    private static final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();

    private static final BigInteger theirNextDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();

    @Test(expected = NullPointerException.class)
    public void testConstructionNullSecureRandom() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(null, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullDHKeyPair() {
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, ourECDHKeyPair, null, theirECDHPublicKey, theirDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullECDHKeyPair() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, null, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullECDHandDHKeyPair() {
        new MixedSharedSecret(RANDOM, null, null, theirECDHPublicKey, theirDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirECDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, null, theirDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirECDHandDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, null, null);
    }

    @Test
    public void testConstruction() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        assertEquals(ourECDHKeyPair.publicKey(), ss.getECDHPublicKey());
        assertEquals(ourDHKeyPair.publicKey(), ss.getDHPublicKey());
        assertEquals(theirECDHPublicKey, ss.getTheirECDHPublicKey());
        assertEquals(theirDHPublicKey, ss.getTheirDHPublicKey());
        assertNotNull(ss.getK());
    }

    @Test
    public void testRotateOurKeysNoDHRatchet() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        final Point firstECDHPublicKey = ss.getECDHPublicKey();
        final BigInteger firstDHPublicKey = ss.getDHPublicKey();
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        final MixedSharedSecret rotated = ss.rotateOurKeys(false);
        // Ensure that k stays the same in original instance.
        assertEquals(firstECDHPublicKey, ss.getECDHPublicKey());
        assertEquals(firstDHPublicKey, ss.getDHPublicKey());
        assertTrue(Arrays.equals(firstK, ss.getK()));
        // Ensure that k actually changes in rotated instance.
        assertNotEquals(firstECDHPublicKey, rotated.getECDHPublicKey());
        assertEquals(firstDHPublicKey, rotated.getDHPublicKey());
        assertFalse(Arrays.equals(firstK, rotated.getK()));
    }

    @Test
    public void testRotateOurKeysDHRatchet() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        final Point firstECDHPublicKey = ss.getECDHPublicKey();
        final BigInteger firstDHPublicKey = ss.getDHPublicKey();
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        final MixedSharedSecret rotated = ss.rotateOurKeys(true);
        // Ensure that k actually changes after rotation.
        assertNotEquals(firstECDHPublicKey, rotated.getECDHPublicKey());
        assertNotEquals(firstDHPublicKey, rotated.getDHPublicKey());
        assertFalse(Arrays.equals(firstK, rotated.getK()));
    }

    @Test
    public void testRotateTheirKeys() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        final MixedSharedSecret rotated = ss.rotateTheirKeys(false, theirNextECDHPublicKey, theirDHPublicKey);
        // Ensure that k and ssid actually change after rotation.
        assertTrue(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstK, rotated.getK()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullECDH() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        ss.rotateTheirKeys(true, null, theirNextDHPublicKey);
    }

    @Test
    public void testRotateTheirKeysNullDHNonThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        final byte[] firstK = ss.getK();
        final byte[] firstSSID = ss.generateSSID();
        // Rotate their public keys.
        final MixedSharedSecret rotated = ss.rotateTheirKeys(false, theirNextECDHPublicKey, theirDHPublicKey);
        // Ensure that k and ssid actually change after rotation.
        assertArrayEquals(firstK, ss.getK());
        assertArrayEquals(firstSSID, ss.generateSSID());
        assertFalse(Arrays.equals(firstK, rotated.getK()));
        assertFalse(Arrays.equals(firstSSID, rotated.generateSSID()));
    }

    @Test
    public void testGetKNotModifiable() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        final MixedSharedSecret rotated = ss.rotateTheirKeys(true, theirNextECDHPublicKey, theirNextDHPublicKey);
        final byte[] firstK = rotated.getK();
        fill(firstK, (byte) 0xff);
        final byte[] secondK = rotated.getK();
        assertFalse(Arrays.equals(firstK, secondK));
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateSamePublicKeysEveryThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        final MixedSharedSecret r1 = ss.rotateOurKeys(true);
        final MixedSharedSecret r2 = ss.rotateTheirKeys(true, theirECDHPublicKey, theirDHPublicKey);
        assertArrayEquals(r1.getK(), r2.getK());
    }

    @Test
    public void testRotateDifferentPublicKeysEveryThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        final MixedSharedSecret r1 = ss.rotateOurKeys(false);
        final byte[] firstK = ss.getK();
        final MixedSharedSecret r2 = ss.rotateTheirKeys(true, theirNextECDHPublicKey, theirNextDHPublicKey);
        assertTrue(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstK, r1.getK()));
        assertFalse(Arrays.equals(firstK, r2.getK()));
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateSamePublicKeysEveryNonThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey, theirDHPublicKey);
        final byte[] firstK = ss.getK();
        final MixedSharedSecret rotated = ss.rotateTheirKeys(false, theirECDHPublicKey, null);
        assertTrue(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstK, rotated.getK()));
    }

    @Test
    public void testRotateOurKeysWithoutTheirKeysNoDHKeyPairRotation() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair, theirECDHPublicKey,
                theirDHPublicKey);
        shared.rotateOurKeys(false);
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysWithNullECDHPoint() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.rotateTheirKeys(true, null, DHKeyPair.generate(RANDOM).publicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysWithIllegalECDHPoint() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.rotateTheirKeys(true, null, DHKeyPair.generate(RANDOM).publicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithOurECDHPublicKey() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair,
                ECDHKeyPair.generate(RANDOM).publicKey(), DHKeyPair.generate(RANDOM).publicKey());
        shared.rotateTheirKeys(true, ourECDHKeyPair.publicKey(), DHKeyPair.generate(RANDOM).publicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithOurDHPublicKey() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ourECDHKeyPair, ourDHKeyPair,
                ECDHKeyPair.generate(RANDOM).publicKey(), DHKeyPair.generate(RANDOM).publicKey());
        shared.rotateTheirKeys(true, ECDHKeyPair.generate(RANDOM).publicKey(), ourDHKeyPair.publicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithTheirCurrentECDHPublicKey() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.rotateTheirKeys(true, theirECDHPublicKey, DHKeyPair.generate(RANDOM).publicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithTheirCurrentDHPublicKey() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.rotateTheirKeys(true, ECDHKeyPair.generate(RANDOM).publicKey(), theirDHPublicKey);
    }

    @Test
    public void testCloseSharedSecret4() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM),theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        assertTrue(allZeroBytes((byte[]) getInternalState(shared, "k")));
        assertTrue(allZeroBytes((byte[]) getInternalState(shared, "braceKey")));
    }

    @Test(expected = IllegalStateException.class)
    public void testRotateTheirKeysAfterClosing() throws OtrCryptoException {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        shared.rotateTheirKeys(true, ECDHKeyPair.generate(RANDOM).publicKey(), theirDHPublicKey);
    }

    @Test(expected = IllegalStateException.class)
    public void testRotateOurKeysAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        shared.rotateOurKeys(true);
    }

    @Test
    public void testGetECDHPublicKeyAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        assertNotNull(shared.getECDHPublicKey());
    }

    @Test
    public void testGetDHPublicKeyAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        assertNotNull(shared.getDHPublicKey());
    }

    @Test
    public void testGetTheirECDHPublicKeyAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        assertNotNull(shared.getTheirECDHPublicKey());
    }

    @Test
    public void testGetTheirDHPublicKeyAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        assertNotNull(shared.getTheirDHPublicKey());
    }

    @Test(expected = IllegalStateException.class)
    public void testGenerateSSIDAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        shared.generateSSID();
    }

    @Test(expected = IllegalStateException.class)
    public void testGetKAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        shared.close();
        shared.getK();
    }

    @Test
    public void testCorrectClearingOfFieldsWhenClosed() {
        final MixedSharedSecret secret = new MixedSharedSecret(RANDOM, ECDHKeyPair.generate(RANDOM),
                DHKeyPair.generate(RANDOM), theirECDHPublicKey, theirDHPublicKey);
        assertFalse(allZeroBytes((byte[]) getInternalState(secret, "k")));
        assertFalse(allZeroBytes((byte[]) getInternalState(secret, "braceKey")));
        assertFalse((Boolean) getInternalState(secret, "closed"));
        secret.close();
        assertTrue(allZeroBytes((byte[]) getInternalState(secret, "k")));
        assertTrue(allZeroBytes((byte[]) getInternalState(secret, "braceKey")));
        assertTrue((Boolean) getInternalState(secret, "closed"));
    }
}
