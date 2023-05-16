/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import com.google.errorprone.annotations.CheckReturnValue;
import com.google.errorprone.annotations.MustBeClosed;
import net.java.otr4j.crypto.MessageKeys;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.logging.Logger;

import static java.lang.Integer.MIN_VALUE;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINER;
import static java.util.logging.Level.FINEST;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.NEXT_CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ROOT_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.Objects.requireEquals;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * The Double Ratchet. (OTRv4)
 * <p>
 * The logistics of the Double Ratchet-algorithm. The mechanism according to which the key rotations are performed. The
 * cryptographic secrets updates are performed in {@link MixedSharedSecret}.
 * <p>
 * Key rotations consist of 2 cases:
 * <ol>
 * <li>Every third ratchet, starting at the first ratchet: rotate the DH key and derive key material from the new DH key
 * pair.</li>
 * <li>Other two ratchets: rotate key material based on symmetric key (brace key) only.</li>
 * </ol>
 * <p>
 * DoubleRatchet is NOT thread-safe.
 */
// TODO DoubleRatchet currently does not keep history. Therefore it is not possible to decode out-of-order messages from previous ratchets. (Also needed to keep MessageKeys instances for messages failing verification.)
final class DoubleRatchet implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DoubleRatchet.class.getName());

    private final ByteArrayOutputStream macsToReveal = new ByteArrayOutputStream();

    /**
     * Sender ratchet (a.k.a. `j`) represents the ratchet process on the part of the message sender.
     * <p>
     * The sender ratchet contains message ID 'j'.
     */
    private final Ratchet senderRatchet = new Ratchet();

    /**
     * Receiver ratchet (a.k.a. `k`) represents the ratchet process on part of the message receiver.
     * <p>
     * The receiver ratchet contains message ID 'k'.
     */
    private final Ratchet receiverRatchet = new Ratchet();

    private final MixedSharedSecret sharedSecret;
    
    // TODO need to eventually perform clean up of `storedKeys` to avoid growing indefinitely, even if only a problem for long run-times.
    private final HashMap<Long, MessageKeys> storedKeys = new HashMap<>();

    /**
     * The 'root key' in the Double Ratchet. The root key is shared between sender and receiver ratchets.
     */
    private final byte[] rootKey;

    /**
     * The next ratchet ID.
     * <p>
     * NOTE: 'i' is incremented as soon as a rotation has finished. For typical use outside of this class, one would use
     * need value 'i - 1', instead of 'i'.
     */
    private int i = 0;

    /**
     * The number of messages in the previous ratchet, i.e. sender ratchet message number.
     */
    private int pn = 0;

    /**
     * Monotonic timestamp of the last rotation activity. ({@link System#nanoTime()})
     */
    private long lastRotation = System.nanoTime();

    DoubleRatchet(final MixedSharedSecret sharedSecret, final byte[] initialRootKey, final Role role) {
        this.sharedSecret = requireNonNull(sharedSecret);
        this.rootKey = requireLengthExactly(ROOT_KEY_LENGTH_BYTES, initialRootKey);
        assert !allZeroBytes(this.rootKey) : "Expected random data, instead of all zero-bytes. There might be something severely wrong.";
        switch (role) {
        case BOB:
            generateRatchetKeys(Purpose.RECEIVING);
            this.senderRatchet.needsRotation = true;
            // As we set the `needsRotation` flag on the sender ratchet, next time a message is sent new ratchet keys
            // will be generated. According to the Double Ratchet initialization in OTRv4 spec, we should do this
            // immediately. However, the steps are exactly the same and generating them here means we need to find a way
            // to put the public keys into the next data message. This makes things a lot more complicated and in the
            // end achieves the exact same effect.
            break;
        case ALICE:
            generateRatchetKeys(Purpose.SENDING);
            break;
        default:
            throw new UnsupportedOperationException("Unsupported purpose.");
        }
    }

    @Override
    public void close() {
        clear(this.rootKey);
        this.i = MIN_VALUE;
        this.pn = 0;
        this.sharedSecret.close();
        if (this.macsToReveal.size() > 0) {
            throw new IllegalStateException("BUG: Remaining MACs have not been revealed.");
        }
        this.senderRatchet.close();
        this.receiverRatchet.close();
    }

    /**
     * Indicates whether or not Sender key rotation is required before encrypting/authenticating the next message to be
     * sent.
     *
     * @return Returns true iff sender key rotation is required.
     */
    @CheckReturnValue
    boolean isNeedSenderKeyRotation() {
        return this.senderRatchet.needsRotation;
    }

    /**
     * The ratchet ID ('i')
     *
     * @return Returns current ratchet ID.
     */
    int getI() {
        return this.i;
    }

    /**
     * The sender message ID ('j')
     *
     * @return Returns message ID.
     */
    int getJ() {
        return this.senderRatchet.messageID;
    }

    /**
     * The receiver message ID ('k')
     *
     * @return Returns message ID.
     */
    int getK() {
        return this.receiverRatchet.messageID;
    }

    /**
     * Number of (sender) messages in previous ratchet.
     *
     * @return Returns number of messages.
     */
    int getPn() {
        return this.pn;
    }

    /**
     * Get the monotonic timestamp for the last sender keys rotation.
     *
     * @return Returns the monotonic timestamp for the last sender keys rotation. ({@link System#nanoTime()})
     */
    long getLastRotation() {
        return this.lastRotation;
    }

    @Nonnull
    Point getECDHPublicKey() {
        return this.sharedSecret.getECDHPublicKey();
    }
    
    @Nonnull
    BigInteger getDHPublicKey() {
        return this.sharedSecret.getDHPublicKey();
    }
    
    @CheckReturnValue
    @Nonnull
    byte[] rotateSenderKeys() {
        requireNotClosed();
        if (!this.senderRatchet.needsRotation) {
            throw new IllegalStateException("Rotation is only allowed after new public key material was received from the other party.");
        }
        // Perform sender key rotation.
        LOGGER.log(FINE, "Rotating root key and sending chain key for ratchet " + this.i);
        this.sharedSecret.rotateOurKeys(this.i % 3 == 0);
        generateRatchetKeys(Purpose.SENDING);
        this.i += 1;
        // Update last-rotation time such that we can keep track of when the last rotation took place.
        this.lastRotation = System.nanoTime();
        // Extract MACs to reveal.
        final byte[] revealedMacs = this.macsToReveal.toByteArray();
        this.macsToReveal.reset();
        return revealedMacs;
    }

    /**
     * Encrypt provided data with the current sending message keys. In the process, generate a nonce required for
     * encryption.
     *
     * @param data the data
     * @return Returns a composite result consisting of the generated nonce and the ciphertext.
     */
    @Nonnull
    byte[] encrypt(final byte[] data) {
        LOGGER.log(FINER, "Generating message keys for encryption of ratchet {0}, message {1}.",
                new Object[]{Math.max(0, this.i - 1), this.senderRatchet.messageID});
        try (MessageKeys keys = this.generateSendingMessageKeys()) {
            return keys.encrypt(data);
        }
    }

    /**
     * Generate an authenticator value for later content verification.
     *
     * @param dataMessageSectionsContent the hash of the data message sections
     * @return Returns authenticator value.
     */
    @Nonnull
    byte[] authenticate(final byte[] dataMessageSectionsContent) {
        LOGGER.log(FINER, "Generating message keys for authentication of ratchet {0}, message {1}.",
                new Object[]{Math.max(0, this.i - 1), this.senderRatchet.messageID});
        try (MessageKeys keys = this.generateSendingMessageKeys()) {
            return keys.authenticate(dataMessageSectionsContent);
        }
    }

    @MustBeClosed
    @Nonnull
    private MessageKeys generateSendingMessageKeys() {
        final byte[] chainkey = this.senderRatchet.getChainKey();
        final MessageKeys keys = MessageKeys.fromChainkey(chainkey);
        clear(chainkey);
        return keys;
    }

    /**
     * Verify then decrypt a received OTRv4 data message.
     *
     * @param ratchetId ID for the receiving ratchet.
     * @param messageId ID for the receiving ratchet message ID.
     * @param encodedDataMessageSections Data message sections that need to be authenticated, encoded as byte-array.
     * @param ciphertext The encrypted message ciphertext.
     * @return Returns the decrypted ciphertext.
     * @throws OtrCryptoException If data message fails verification, i.e. the authenticators do not match.
     * @throws RotationLimitationException In case of failure to acquire the corresponding message keys. This exception
     * occurs when the first message of a new message is missing and therefore we
     * cannot generate the necessary keys.
     */
    byte[] decrypt(final int ratchetId, final int messageId, final byte[] encodedDataMessageSections,
            final byte[] authenticator, final byte[] ciphertext) throws RotationLimitationException, OtrCryptoException {
        LOGGER.log(FINER, "Generating message keys for verification and decryption of ratchet {0}, message {1}.",
                new Object[]{this.i - 1, this.receiverRatchet.messageID});
        try (MessageKeys keys = generateReceivingMessageKeys(ratchetId, messageId)) {
            keys.verify(encodedDataMessageSections, authenticator);
            this.macsToReveal.write(authenticator, 0, authenticator.length);
            return keys.decrypt(ciphertext);
        }
    }

    /**
     * Acquire the extra symmetric key that corresponds to the next message to be sent.
     * <p>
     * Note that this is the "raw" extra symmetric key. OTRv4 specifies how one can derive additional keys from this
     * "raw" input data. These derivation steps are not performed. (See {@link OtrCryptoEngine4#deriveExtraSymmetricKey(int, byte[], byte[])})
     *
     * @return The "raw" extra symmetric key. (User needs to clean up the byte-array after use.)
     */
    @Nonnull
    byte[] extraSymmetricKeySender() {
        requireNotClosed();
        LOGGER.log(FINEST, "Generating extra symmetric keys for encryption of ratchet {0}, message {1}.",
                new Object[] {Math.max(this.i, 0), this.senderRatchet.messageID});
        try (MessageKeys keys = generateSendingMessageKeys()) {
            // This is the "raw" extra symmetric key. The OTRv4 spec shortly touches on taking derivative keys from this
            // key, therefore we return the raw bytes.
            return keys.getExtraSymmetricKey();
        }
    }

    /**
     * Acquire the extra symmetric key that corresponds to received messages.
     *
     * @return The "raw" extra symmetric key. (User needs to clean up the byte-array after use.)
     */
    @Nonnull
    byte[] extraSymmetricKeyReceiver(final int ratchetId, final int messageId) throws RotationLimitationException {
        requireNotClosed();
        LOGGER.log(FINEST, "Generating extra symmetric keys for encryption of ratchet {0}, message {1}.",
                new Object[]{ratchetId, messageId});
        try (MessageKeys keys = generateReceivingMessageKeys(ratchetId, messageId)) {
            return keys.getExtraSymmetricKey();
        }
    }

    /**
     * Generate receiving Message Keys.
     *
     * @param ratchetId The ratchet ID as indicated in the Data message.
     * @param messageId The message ID as indicated in the Data message.
     * @return Returns corresponding MessageKeys instance.
     * @throws RotationLimitationException Indicates that we cross a ratchet boundary and therefore we cannot fast-forward
     *                               rotations to a point where the right message keys can be generated. This is a
     *                               limitation of the Double Ratchet. Matching message keys cannot be generated.
     */
    @SuppressWarnings("MustBeClosedChecker")
    @MustBeClosed
    private MessageKeys generateReceivingMessageKeys(final int ratchetId, final int messageId) throws RotationLimitationException {
        // TODO WARNING: the generated message keys should not modify state in any way. We cannot affect state until the data message is authenticated. (This must be implemented in a fool-proof way.)
        requireNotClosed();
        final int currentRatchet = Math.max(0, this.i - 1);
        if (ratchetId > currentRatchet) {
            // If all necessary keys are available, we should rotate receiving ratchet receiving (public) keys. 
            throw new RotationLimitationException("BUG: cannot fast-forward receiving message keys into a new ratchet.");
        }
        if (ratchetId < currentRatchet || messageId < this.receiverRatchet.messageID) {
            // Message keys are in ratchet history, so check the store for possible stored keys.
            final MessageKeys keys = this.storedKeys.get((long) ratchetId << 32 | messageId);
            if (keys == null) {
                throw new RotationLimitationException("No message keys stored.");
            }
            // Copy message keys to ensure they are available (and uncleared) if a second request comes in, e.g. the
            // extra symmetric key.
            return keys.copy();
        }
        final byte[] chainkey = this.receiverRatchet.simulate().rotateChainKey(messageId);
        final MessageKeys keys = MessageKeys.fromChainkey(chainkey);
        clear(chainkey);
        return keys;
    }

    /**
     * Rotate the sending chain key.
     */
    void rotateSendingChainKey() {
        this.senderRatchet.rotateChainKey();
    }

    /**
     * Rotate the receiving chain key.
     */
    // FIXME keep a latest confirmed messageId on every call to rotateReceivingChainKey, because that is called after successfully authentication and decrypting the data message.
    void rotateReceivingChainKey(final int ratchetId, final int messageId) {
        final int currentRatchet = Math.max(0, this.i - 1);
        if (ratchetId > currentRatchet) {
            throw new IllegalArgumentException("BUG: Ratcheting is required.");
        }
        if (ratchetId < currentRatchet || messageId < this.receiverRatchet.messageID) {
            // If we previously retrieved the keys from the store, clear the keys from the store.
            LOGGER.log(FINER, "Rotate receiver chainkey: clear stored chainkey {0}, {1}",
                    new Object[]{ratchetId, messageId});
            final MessageKeys oldkeys = this.storedKeys.remove((long) ratchetId << 32 | messageId);
            requireNonNull(oldkeys, "BUG: we rotate away from keys that were just used. These should exist in the store.");
            oldkeys.close();
            return;
        }
        // TODO verify that number of messages needing to fast-forward is acceptable. (max_skip in OTRv4 spec)
        while (messageId > this.receiverRatchet.messageID) {
            LOGGER.log(FINEST, "Fast-forward rotating receiving chain key to catch up with message ID: {0}",
                    new Object[]{messageId});
            // After every successful decrypting of a received message, the receiving chain key is also rotated away.
            // This means that the current receiving message ID (`K`) is always a key not used successfully before.
            // (A failed attempt at decrypting a corrupt/fake message is still possible.)
            this.storedKeys.put((long) currentRatchet << 32 | this.receiverRatchet.messageID,
                    MessageKeys.fromChainkey(this.receiverRatchet.getChainKey()));
            this.receiverRatchet.rotateChainKey();
        }
        if (messageId == this.receiverRatchet.messageID) {
            LOGGER.log(FINER, "Rotate receiver chainkey: rotating to next chainkey {0}, {1}",
                    new Object[]{ratchetId, messageId});
            this.receiverRatchet.rotateChainKey();
        }
    }

    /**
     * Rotate the receiver key.
     * <p>
     * For convenience, it is allowed to pass in null for each of the keys. Depending on the input, a key rotation will
     * be performed, or it will be skipped.
     *
     * @param nextECDH The other party's ECDH public key.
     * @param nextDH   The other party's DH public key.
     * @throws OtrCryptoException thrown if provided public keys are illegal.
     */
    void rotateReceiverKeys(final Point nextECDH, @Nullable final BigInteger nextDH) throws OtrCryptoException {
        requireNotClosed();
        requireEquals(this.i % 3 == 0, nextDH != null,
                "BUG: nextDH must be provided for 'third brace key' rotations");
        LOGGER.log(FINE, "Rotating root key and receiving chain key for ratchet {0} (nextDH = {1})",
                new Object[]{this.i, nextDH != null});
        if (nextECDH.constantTimeEquals(this.sharedSecret.getTheirECDHPublicKey())
                || (this.i % 3 == 0 && this.sharedSecret.getTheirDHPublicKey().equals(nextDH))) {
            LOGGER.log(FINE, "Skipping rotating receiver keys as ECDH public key is already known.");
            return;
        }
        // TODO preserve message keys before ratcheting. (use 'pn', needs authentication)
        this.sharedSecret.rotateTheirKeys(nextECDH, nextDH);
        this.pn = this.senderRatchet.messageID;
        generateRatchetKeys(Purpose.RECEIVING);
        this.senderRatchet.needsRotation = true;
        this.i += 1;
    }

    private void generateRatchetKeys(final Purpose purpose) {
        final byte[] previousRootKey = this.rootKey.clone();
        final byte[] newK = this.sharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(previousRootKey, newK);
        kdf(this.rootKey, 0, ROOT_KEY_LENGTH_BYTES, ROOT_KEY, concatPreviousRootKeyNewK);
        switch (purpose) {
        case SENDING:
            this.senderRatchet.rotateKeys(concatPreviousRootKeyNewK);
            break;
        case RECEIVING:
            this.receiverRatchet.rotateKeys(concatPreviousRootKeyNewK);
            break;
        default:
            throw new UnsupportedOperationException("Unsupported parameter: " + purpose);
        }
        clear(newK);
        clear(previousRootKey);
        clear(concatPreviousRootKeyNewK);
    }

    /**
     * Get the remaining MAC-keys-to-be-revealed. (And remove them from the internal list to be revealed.)
     * <p>
     * NOTE: this method should only used to acquire the last remaining MAC keys prior to a session end. The general
     * revelation case is facilitated through key rotation, i.e. {@link #rotateSenderKeys()}.
     *
     * @return Returns the remaining MAC keys to reveal.
     */
    byte[] collectRemainingMACsToReveal() {
        requireNotClosed();
        final byte[] revealed = this.macsToReveal.toByteArray();
        this.macsToReveal.reset();
        return revealed;
    }

    /**
     * Forget the remaining MAC-keys-to-be-revealed. (This is called whenever remaining MAC keys need not be revealed
     * before actually closing.)
     */
    void forgetRemainingMACsToReveal() {
        requireNotClosed();
        this.macsToReveal.reset();
    }

    private void requireNotClosed() {
        if (this.i < 0) {
            throw new IllegalStateException("Instance was previously closed and cannot be used anymore.");
        }
    }

    /**
     * Ratchet, the individual ratchet used for either sending or receiving.
     */
    private final static class Ratchet implements AutoCloseable {

        private static final int CHAIN_KEY_LENGTH_BYTES = 64;

        /**
         * The chain key.
         * <p>
         * The key relies on a first key rotation to become initialized.
         */
        private final byte[] chainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

        /**
         * Message ID.
         */
        private int messageID = 0;

        /**
         * The boolean indicates that we need key rotation before we have sensible data to work with. (Initially, the
         * chain key is all-zero.)
         */
        private boolean needsRotation = false;

        @Override
        public void close() {
            this.messageID = MIN_VALUE;
            clear(this.chainKey);
        }

        @Nonnull
        RatchetSimula simulate() {
            return new RatchetSimula(this.chainKey.clone(), this.messageID);
        }

        /**
         * Acquire ratchet's chain key.
         * <p>
         * NOTE: caller needs to clear the return key after use.
         *
         * @return Returns chain key.
         */
        byte[] getChainKey() {
            requireNotClosed();
            requireRotationNotNeeded();
            return this.chainKey.clone();
        }

        /**
         * Rotate the chain key.
         * <p>
         * Generate a new chain key based on the old chain key and increment the message ID.
         */
        void rotateChainKey() {
            requireNotClosed();
            requireRotationNotNeeded();
            this.messageID += 1;
            kdf(this.chainKey, 0, CHAIN_KEY_LENGTH_BYTES, NEXT_CHAIN_KEY, this.chainKey);
        }

        /**
         * Rotate the ratchet key.
         */
        void rotateKeys(final byte[] concatPreviousRootKeyNewK) {
            requireNotClosed();
            this.messageID = 0;
            kdf(this.chainKey, 0, CHAIN_KEY_LENGTH_BYTES, CHAIN_KEY, concatPreviousRootKeyNewK);
            this.needsRotation = false;
        }

        private void requireRotationNotNeeded() {
            if (this.needsRotation) {
                throw new IllegalStateException("Key rotation needs to be performed before new keys can be generated.");
            }
        }

        private void requireNotClosed() {
            if (this.messageID < 0) {
                throw new IllegalStateException("Ratchet instance is already closed.");
            }
        }
    }
    
    private static final class RatchetSimula {

        private static final int CHAIN_KEY_LENGTH_BYTES = 64;

        /**
         * The chain key.
         * <p>
         * The key relies on a first key rotation to become initialized.
         */
        // TODO needs to be cleared after use
        private final byte[] chainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

        /**
         * Message ID.
         */
        private final int messageID;

        private RatchetSimula(final byte[] chainKey, final int id) {
            System.arraycopy(chainKey, 0, this.chainKey, 0, this.chainKey.length);
            this.messageID = id;
        }

        /**
         * Rotate the chain key.
         * <p>
         * Generate a new chain key based on the old chain key and increment the message ID.
         */
        @Nonnull
        byte[] rotateChainKey(final int target) {
            final byte[] localChainKey = Arrays.copyOf(this.chainKey, this.chainKey.length);
            for (int i = this.messageID; i < target; i++) {
                kdf(localChainKey, 0, CHAIN_KEY_LENGTH_BYTES, NEXT_CHAIN_KEY, localChainKey);
            }
            return localChainKey;
        }
    }

    /**
     * This is used to indicate that a boundary is reached that the DoubleRatchet cannot handle.
     */
    static final class RotationLimitationException extends Exception {

        private static final long serialVersionUID = -2200918867384812098L;

        private RotationLimitationException(final String message) {
            super(message);
        }
    }

    /**
     * The role which is fulfilled according to the OTRv4 specification.
     */
    enum Role {
        ALICE, BOB
    }

    private enum Purpose {
        SENDING, RECEIVING
    }
}
