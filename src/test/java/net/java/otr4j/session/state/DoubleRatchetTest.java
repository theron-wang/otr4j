/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;
import net.java.otr4j.util.Classes;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.MK_MAC_LENGTH_BYTES;
import static net.java.otr4j.session.state.DoubleRatchet.Purpose.RECEIVING;
import static net.java.otr4j.session.state.DoubleRatchet.Purpose.SENDING;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.Classes.readValue;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@SuppressWarnings({"ConstantConditions", "resource", "ResultOfMethodCallIgnored"})
public class DoubleRatchetTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] MESSAGE = "Hello world".getBytes(UTF_8);

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullSharedSecret() {
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        DoubleRatchet.initialize(SENDING, null, initialRootKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullInitialRootKey() {
        DoubleRatchet.initialize(SENDING, generateSharedSecret(), null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructDoubleRatchetNullPurpose() {
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        DoubleRatchet.initialize(null, generateSharedSecret(), initialRootKey);
    }

    @Test
    public void testConstructDoubleRatchet() {
        DoubleRatchet.initialize(SENDING, generateSharedSecret(), randomBytes(RANDOM, new byte[64]));
        DoubleRatchet.initialize(RECEIVING, generateSharedSecret(), randomBytes(RANDOM, new byte[64]));
    }

    @Test(expected = IllegalStateException.class)
    public void testRotateBeforeReceptionNotPermitted() {
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = DoubleRatchet.initialize(SENDING, generateSharedSecret(), initialRootKey);
        ratchet.rotateSenderKeys();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testEncryptionAfterRotation() {
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        DoubleRatchet ratchet = DoubleRatchet.initialize(RECEIVING, generateSharedSecret(), initialRootKey);
        ratchet = ratchet.rotateSenderKeys();
        final byte[] ciphertext = ratchet.encrypt(MESSAGE);
        assertFalse(allZeroBytes(ciphertext));
        assertFalse(Arrays.equals(MESSAGE, ciphertext));
    }

    @Test
    public void testAuthenticationAfterRotation() {
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        DoubleRatchet ratchet = DoubleRatchet.initialize(RECEIVING, generateSharedSecret(), initialRootKey);
        ratchet = ratchet.rotateSenderKeys();
        final byte[] auth1 = ratchet.authenticate(MESSAGE);
        final byte[] auth2 = ratchet.authenticate(MESSAGE);
        assertArrayEquals(auth1, auth2);
    }

    @Test
    public void testAuthenticatorsDifferentAfterRotation() {
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        DoubleRatchet ratchet = DoubleRatchet.initialize(RECEIVING, generateSharedSecret(), initialRootKey);
        ratchet = ratchet.rotateSenderKeys();
        final int firstMessageId = ratchet.getJ();
        final byte[] auth1 = ratchet.authenticate(MESSAGE);
        ratchet.rotateSendingChainKey();
        assertNotEquals(firstMessageId, ratchet.getJ());
        final byte[] auth2 = ratchet.authenticate(MESSAGE);
        assertFalse(Arrays.equals(auth1, auth2));
    }

    @Test
    public void testRepeatedCloseIsAllowed() {
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = DoubleRatchet.initialize(SENDING, generateSharedSecret(), initialRootKey);
        ratchet.close();
        ratchet.close();
        ratchet.close();
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsEncryption() {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = DoubleRatchet.initialize(SENDING, generateSharedSecret(), initialRootKey);
        ratchet.close();
        ratchet.encrypt(message);
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsVerify() throws RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello World!".getBytes(UTF_8);
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = DoubleRatchet.initialize(SENDING, generateSharedSecret(), initialRootKey);
        ratchet.rotateSenderKeys();
        final byte[] authenticator = ratchet.authenticate(message);
        ratchet.close();
        ratchet.decrypt(ratchet.getI(), ratchet.getJ(), message, authenticator, new byte[0]);
    }

    @Test(expected = IllegalStateException.class)
    public void testMessageKeysClosedFailsGetExtraSymmetricKey() {
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = DoubleRatchet.initialize(SENDING, generateSharedSecret(), initialRootKey);
        ratchet.close();
        ratchet.rotateSenderKeys();
    }

    @Test
    public void testDoubleRatchetWorksSymmetrically() throws RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING, new MixedSharedSecret(RANDOM, bobFirstECDH,
                bobFirstDH, aliceFirstECDH.publicKey(), aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING, new MixedSharedSecret(RANDOM, aliceFirstECDH,
                aliceFirstDH, bobFirstECDH.publicKey(), bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet = aliceRatchet.rotateSenderKeys();
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey(), 0);
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, message, authenticator, ciphertext));
    }

    @Test(expected = OtrCryptoException.class)
    public void testDoubleRatchetWorksBadAuthenticator() throws RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());
        aliceRatchet = aliceRatchet.rotateSenderKeys();
        bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey(), 4);
        bobRatchet.decrypt(0, 0, message, randomBytes(RANDOM, new byte[64]), randomBytes(RANDOM, new byte[100]));
    }

    @Test(expected = IllegalStateException.class)
    public void testDoubleRatchetPrematureClosing() throws RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet = aliceRatchet.rotateSenderKeys();
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey(), 0);
        bobRatchet.decrypt(0, 0, message, authenticator, ciphertext);
        bobRatchet.close();
    }

    @Test
    public void testDoubleRatchetClosingClearsSensitiveData() throws RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet = aliceRatchet.rotateSenderKeys();
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey(), 0);
        bobRatchet.decrypt(0, 0, message, authenticator, ciphertext);
        bobRatchet.collectReveals();
        assertFalse(allZeroBytes(Classes.readValue(byte[].class, bobRatchet, "rootKey")));
        assertFalse(allZeroBytes(Classes.readValue(byte[].class, bobRatchet, "senderRatchet", "chainKey")));
        assertFalse(allZeroBytes(Classes.readValue(byte[].class, bobRatchet, "receiverRatchet", "chainKey")));
        bobRatchet.close();
        assertEquals(0, Classes.readValue(ByteArrayOutputStream.class, bobRatchet, "reveals").size());
        assertTrue(allZeroBytes(Classes.readValue(byte[].class, bobRatchet, "rootKey")));
        assertTrue(allZeroBytes(Classes.readValue(byte[].class, bobRatchet, "senderRatchet", "chainKey")));
        assertTrue(allZeroBytes(Classes.readValue(byte[].class, bobRatchet, "receiverRatchet", "chainKey")));
    }

    @Test
    public void testDoubleRatchetSkipMessagesLostMessageKeys() throws RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet = aliceRatchet.rotateSenderKeys();
        aliceRatchet.rotateSendingChainKey();
        aliceRatchet.rotateSendingChainKey();
        final byte[] ciphertext2 = aliceRatchet.encrypt(message);
        final byte[] authenticator2 = aliceRatchet.authenticate(message);
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey(), 0);
        assertArrayEquals(message, bobRatchet.decrypt(0, 2, message, authenticator2, ciphertext2));
    }

    @Test
    public void testDoubleRatchetRetrievePreviousMessageKeys() throws RotationLimitationException, OtrCryptoException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet = aliceRatchet.rotateSenderKeys();
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(ciphertext);
        aliceRatchet.rotateSendingChainKey();
        final byte[] message2 = "Hello again.".getBytes(UTF_8);
        final byte[] ciphertext2 = aliceRatchet.encrypt(message2);
        final byte[] authn2 = aliceRatchet.authenticate(ciphertext2);
        aliceRatchet.rotateSendingChainKey();
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey(), 0);
        bobRatchet.decrypt(0, 1, ciphertext2, authn2, ciphertext2);
        bobRatchet.confirmReceivingChainKey(0, 1);
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, ciphertext, authenticator, ciphertext));
        bobRatchet.confirmReceivingChainKey(0, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDoubleRatchetSkipMessageKeysPastRatchet() throws RotationLimitationException, OtrCryptoException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceECDH, aliceDH, bobECDH.publicKey(), bobDH.publicKey()),
                initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        aliceRatchet.rotateSenderKeys();
        // ... in the mean time Bob rotates, encrypts messages and sends them to Alice.
        // ... Alice, however, does not receive all of them. Until, receiving message 2, 1, for which receiver keys
        // rotation is needed.
        aliceRatchet.decrypt(2, 1, new byte[0], new byte[0], new byte[0]);
    }

    // TODO are there tests that intentionally trigger the failure case where the nextDH key is provided inappropriately?
    @Test
    public void testDoubleRatchetWorksSymmetricallyWithRotations() throws RotationLimitationException, OtrCryptoException {
        final byte[] message = "Hello Alice!".getBytes(UTF_8);
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        assertEquals(SENDING, aliceRatchet.nextRotation());
        try (DoubleRatchet ignored = aliceRatchet) {
            aliceRatchet = aliceRatchet.rotateSenderKeys();
            ignored.getI(); // dummy to prevent compiler complaints
        }
        assertArrayEquals(new byte[0], aliceRatchet.collectReveals());
        assertEquals(RECEIVING, aliceRatchet.nextRotation());
        final byte[] ciphertext = aliceRatchet.encrypt(message);
        final byte[] authenticator = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey1 = aliceRatchet.extraSymmetricKeySender();
        aliceRatchet.rotateSendingChainKey();
        final byte[] ciphertext2 = aliceRatchet.encrypt(message);
        final byte[] authenticator2 = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey2 = aliceRatchet.extraSymmetricKeySender();
        aliceRatchet.rotateSendingChainKey();
        final byte[] ciphertext3 = aliceRatchet.encrypt(message);
        final byte[] authenticator3 = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey3 = aliceRatchet.extraSymmetricKeySender();
        aliceRatchet.rotateSendingChainKey();
        // Start decrypting and verifying using Alice's double ratchet.
        try (DoubleRatchet ignored = bobRatchet) {
            bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey(),
                    aliceRatchet.getJ());
            ignored.getI(); // dummy to prevent compiler complaints
        }
        assertEquals(SENDING, bobRatchet.nextRotation());
        assertEquals(1, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(0, bobRatchet.getK());
        assertEquals(0, bobRatchet.getPn());
        assertArrayEquals(message, bobRatchet.decrypt(0, 0, message, authenticator, ciphertext));
        assertArrayEquals(extraSymmKey1, bobRatchet.extraSymmetricKeyReceiver(0, 0));
        bobRatchet.confirmReceivingChainKey(0, 0);
        assertEquals(1, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(1, bobRatchet.getK());
        assertArrayEquals(message, bobRatchet.decrypt(0, 1, message, authenticator2, ciphertext2));
        assertArrayEquals(extraSymmKey2, bobRatchet.extraSymmetricKeyReceiver(0, 1));
        bobRatchet.confirmReceivingChainKey(0, 1);
        assertEquals(1, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(2, bobRatchet.getK());
        assertArrayEquals(message, bobRatchet.decrypt(0, 2, message, authenticator3, ciphertext3));
        assertArrayEquals(extraSymmKey3, bobRatchet.extraSymmetricKeyReceiver(0, 2));
        bobRatchet.confirmReceivingChainKey(0, 2);
        assertEquals(1, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        // Bob starts sending response messages.
        final byte[] revealedMacs2;
        try (DoubleRatchet previous = bobRatchet) {
            bobRatchet = bobRatchet.rotateSenderKeys();
            revealedMacs2 = previous.collectReveals();
        }
        assertEquals(0, revealedMacs2.length % MK_MAC_LENGTH_BYTES);
        assertEquals(3 * MK_MAC_LENGTH_BYTES, revealedMacs2.length);
        assertEquals(RECEIVING, bobRatchet.nextRotation());
        assertEquals(2, bobRatchet.getI());
        assertEquals(0, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final byte[] ciphertext4 = bobRatchet.encrypt(message);
        final byte[] authenticator4 = bobRatchet.authenticate(message);
        final byte[] extraSymmKey4 = bobRatchet.extraSymmetricKeySender();
        bobRatchet.rotateSendingChainKey();
        assertEquals(2, bobRatchet.getI());
        assertEquals(1, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final byte[] ciphertext5 = bobRatchet.encrypt(message);
        final byte[] authenticator5 = bobRatchet.authenticate(message);
        final byte[] extraSymmKey5 = bobRatchet.extraSymmetricKeySender();
        bobRatchet.rotateSendingChainKey();
        assertEquals(2, bobRatchet.getI());
        assertEquals(2, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        final byte[] ciphertext6 = bobRatchet.encrypt(message);
        final byte[] authenticator6 = bobRatchet.authenticate(message);
        final byte[] extraSymmKey6 = bobRatchet.extraSymmetricKeySender();
        bobRatchet.rotateSendingChainKey();
        assertEquals(2, bobRatchet.getI());
        assertEquals(3, bobRatchet.getJ());
        assertEquals(3, bobRatchet.getK());
        // Alice starts decrypting and verifying the responses.
        assertEquals(RECEIVING, aliceRatchet.nextRotation());
        try (DoubleRatchet ignored = aliceRatchet) {
            aliceRatchet = aliceRatchet.rotateReceiverKeys(bobRatchet.getECDHPublicKey(), null, bobRatchet.getJ());
            ignored.getI(); // dummy to prevent compiler complaints
        }
        assertEquals(SENDING, aliceRatchet.nextRotation());
        assertEquals(0, aliceRatchet.getPn());
        assertEquals(2, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(0, aliceRatchet.getK());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 0, message, authenticator4, ciphertext4));
        assertArrayEquals(extraSymmKey4, aliceRatchet.extraSymmetricKeyReceiver(1, 0));
        aliceRatchet.confirmReceivingChainKey(1, 0);
        assertEquals(2, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(1, aliceRatchet.getK());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 1, message, authenticator5, ciphertext5));
        assertArrayEquals(extraSymmKey5, aliceRatchet.extraSymmetricKeyReceiver(1, 1));
        aliceRatchet.confirmReceivingChainKey(1, 1);
        assertEquals(2, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(2, aliceRatchet.getK());
        assertArrayEquals(message, aliceRatchet.decrypt(1, 2, message, authenticator6, ciphertext6));
        assertArrayEquals(extraSymmKey6, aliceRatchet.extraSymmetricKeyReceiver(1, 2));
        aliceRatchet.confirmReceivingChainKey(1, 2);
        assertEquals(2, aliceRatchet.getI());
        assertEquals(3, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        // Verify that Alice reveals the expected authenticators.
        try (DoubleRatchet previous = aliceRatchet) {
            aliceRatchet = aliceRatchet.rotateSenderKeys();
            assertEquals(3 * MK_MAC_LENGTH_BYTES, previous.collectReveals().length);
        }
        assertEquals(RECEIVING, aliceRatchet.nextRotation());
        assertEquals(3, aliceRatchet.getI());
        assertEquals(0, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        final byte[] ciphertext7 = aliceRatchet.encrypt(message);
        final byte[] authenticator7 = aliceRatchet.authenticate(message);
        final byte[] extraSymmKey7 = aliceRatchet.extraSymmetricKeySender();
        aliceRatchet.rotateSendingChainKey();
        assertEquals(3, aliceRatchet.getI());
        assertEquals(1, aliceRatchet.getJ());
        assertEquals(3, aliceRatchet.getK());
        assertEquals(0, aliceRatchet.collectReveals().length);
        aliceRatchet.close();
        assertEquals(RECEIVING, bobRatchet.nextRotation());
        try (DoubleRatchet previous = bobRatchet) {
            bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), null, 1);
            assertEquals(0, previous.collectReveals().length);
        }
        assertEquals(SENDING, bobRatchet.nextRotation());
        assertEquals(0, bobRatchet.getPn());
        assertEquals(3, bobRatchet.getI());
        assertEquals(3, bobRatchet.getJ());
        assertEquals(0, bobRatchet.getK());
        assertArrayEquals(message, bobRatchet.decrypt(2, 0, message, authenticator7, ciphertext7));
        assertEquals(MK_MAC_LENGTH_BYTES, bobRatchet.collectReveals().length);
        assertArrayEquals(extraSymmKey7, bobRatchet.extraSymmetricKeyReceiver(2, 0));
        bobRatchet.close();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDoubleRatchetSignalsMissingNextDH() throws OtrCryptoException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        final DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        assertEquals(SENDING, aliceRatchet.nextRotation());
        final DoubleRatchet rotated = aliceRatchet.rotateSenderKeys();
        assertEquals(SENDING, aliceRatchet.nextRotation());
        assertEquals(RECEIVING, rotated.nextRotation());
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet.rotateReceiverKeys(rotated.getECDHPublicKey(), null, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDoubleRatchetSignalsUnexpectedNextDH() throws OtrCryptoException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        assertEquals(SENDING, aliceRatchet.nextRotation());
        aliceRatchet = aliceRatchet.rotateSenderKeys();
        assertEquals(RECEIVING, aliceRatchet.nextRotation());
        // Start decrypting and verifying using Alice's double ratchet.
        bobRatchet = bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), aliceRatchet.getDHPublicKey(), 0);
        bobRatchet = bobRatchet.rotateSenderKeys();
        aliceRatchet.rotateReceiverKeys(bobRatchet.getECDHPublicKey(), bobRatchet.getDHPublicKey(), 0);
    }

    @Test(expected = OtrCryptoException.class)
    public void testDoubleRatchetSignalsReusedNextDH() throws OtrCryptoException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DHKeyPair aliceFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair aliceFirstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair bobFirstDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair bobFirstECDH = ECDHKeyPair.generate(RANDOM);
        DoubleRatchet bobRatchet = DoubleRatchet.initialize(SENDING,
                new MixedSharedSecret(RANDOM, bobFirstECDH, bobFirstDH, aliceFirstECDH.publicKey(),
                        aliceFirstDH.publicKey()), initialRootKey.clone());
        DoubleRatchet aliceRatchet = DoubleRatchet.initialize(RECEIVING,
                new MixedSharedSecret(RANDOM, aliceFirstECDH, aliceFirstDH, bobFirstECDH.publicKey(),
                        bobFirstDH.publicKey()), initialRootKey.clone());

        // Start encrypting and authenticating using Bob's double ratchet.
        assertEquals(SENDING, aliceRatchet.nextRotation());
        aliceRatchet = aliceRatchet.rotateSenderKeys();
        assertEquals(RECEIVING, aliceRatchet.nextRotation());
        // Rotate receiving keys using Bob's first DH s.t. we use a known public key, which is illegal.
        bobRatchet.rotateReceiverKeys(aliceRatchet.getECDHPublicKey(), bobFirstDH.publicKey(), 0);
    }

    @Test
    public void testGenerateExtraSymmetricKeys() throws RotationLimitationException, OtrCryptoException {
        // Prepare ratchets for Alice and Bob
        final byte[] initialRootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = DoubleRatchet.initialize(RECEIVING, generateSharedSecret(), initialRootKey.clone());
        // Rotate sender keys and generate sender extra symmetric key
        assertEquals(SENDING, ratchet.nextRotation());
        final DoubleRatchet rotated = ratchet.rotateSenderKeys();
        assertEquals(SENDING, ratchet.nextRotation());
        assertEquals(RECEIVING, rotated.nextRotation());
        final byte[] extraSymmSendingKey = rotated.extraSymmetricKeySender();
        assertNotNull(extraSymmSendingKey);
        assertFalse(allZeroBytes(extraSymmSendingKey));
        // Rotate receiver keys and generate receiver extra symmetric key
        final DoubleRatchet rotated2 = rotated.rotateReceiverKeys(ECDHKeyPair.generate(RANDOM).publicKey(), null, 0);
        rotated.extraSymmetricKeyReceiver(0, 0);
        final byte[] extraSymmReceivingKey = rotated2.extraSymmetricKeyReceiver(1, 0);
        assertNotNull(extraSymmReceivingKey);
        assertFalse(allZeroBytes(extraSymmReceivingKey));
    }

    private MixedSharedSecret generateSharedSecret() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        return new MixedSharedSecret(RANDOM, ecdhKeyPair, dhKeyPair, theirECDHPublicKey, theirDHPublicKey);
    }
}
