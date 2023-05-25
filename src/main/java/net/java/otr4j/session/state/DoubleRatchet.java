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
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static java.lang.Integer.MIN_VALUE;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINER;
import static java.util.logging.Level.FINEST;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.NEXT_CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.MK_MAC_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ROOT_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.clear;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.Integers.requireEquals;
import static net.java.otr4j.util.Objects.requireNotEquals;
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
// TODO current idempotent rotation procedure (to start DoubleRatchet changes provisional) require a lot of copying/cloning data. Can we do this in a more efficient way?
// FIXME set-up clean up, revealed MAC keys, ...
// FIXME carefully inspect that this way of working with "provisional" ratchet instance, does indeed not leave any changes/traces. (public key handling .. closing keypairs when rotating receiver keys?)
final class DoubleRatchet implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DoubleRatchet.class.getName());

    /**
     * Monotonic timestamp of the last rotation activity. ({@link System#nanoTime()})
     */
    private final long lastRotation = System.nanoTime();

    /**
     * The next ratchet ID.
     * <p>
     * NOTE: 'i' is incremented as soon as a rotation has finished. For typical use outside of this class, one would use
     * need value 'i - 1', instead of 'i'.
     */
    private final int i;

    /**
     * The number of messages in the previous ratchet, i.e. sender ratchet message number.
     */
    private final int pn;

    private final MixedSharedSecret sharedSecret;

    /**
     * The 'root key' in the Double Ratchet. The root key is shared between sender and receiver ratchets.
     */
    @Nonnull
    private final byte[] rootKey;

    /**
     * Sender ratchet (a.k.a. `j`) represents the ratchet process on the part of the message sender.
     * <p>
     * The sender ratchet contains message ID 'j'.
     */
    @Nonnull
    private final Ratchet senderRatchet;

    /**
     * Receiver ratchet (a.k.a. `k`) represents the ratchet process on part of the message receiver.
     * <p>
     * The receiver ratchet contains message ID 'k'.
     */
    @Nonnull
    private final Ratchet receiverRatchet;

    /**
     * nextRotation indicates which of the ratchets needs to be rotated next.
     */
    @Nonnull
    private final Purpose nextRotation;

    // TODO need to eventually perform clean up of `storedKeys` (inject MK_MACs into `macsToReveal`, see spec) to avoid growing indefinitely, even if only a problem for long run-times.
    // TODO spec dictates to store message keys under composite key (`ECDH public key`, `messageId`) which is not what we currently do. (Do we care if we already authenticate the message before committing changes.)
    private final HashMap<Long, MessageKeys> storedKeys;

    /**
     * MAC keys to be revealed. (in spec `mac_keys_to_reveal`)
     */
    // TODO fine-tuning revealing of MAC keys: (OTRv4) "A MAC key is added to `mac_keys_to_reveal` list after a participant has verified the message associated with that MAC key. They are also added if the session is expired or when the storage of message keys gets deleted, and the MAC keys for messages that have not arrived are derived."
    private final ByteArrayOutputStream reveals = new ByteArrayOutputStream();

    static DoubleRatchet initialize(final Purpose purpose, final MixedSharedSecret sharedSecret,
            final byte[] firstRootKey) {
        requireLengthExactly(ROOT_KEY_LENGTH_BYTES, firstRootKey);
        assert !allZeroBytes(firstRootKey) : "Expecting random data instead of all zero-bytes. There might be something severely wrong.";
        final byte[] newK = sharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(firstRootKey, newK);
        final Ratchet sender, receiver;
        final Purpose next;
        switch (purpose) {
        case SENDING:
            sender = Ratchet.create(concatPreviousRootKeyNewK);
            receiver = Ratchet.INITIAL;
            next = Purpose.RECEIVING;
            break;
        case RECEIVING:
            sender = Ratchet.INITIAL;
            receiver = Ratchet.create(concatPreviousRootKeyNewK);
            next = Purpose.SENDING;
            break;
        default:
            throw new UnsupportedOperationException("BUG: unsupported purpose encountered.");
        }
        clear(newK);
        clear(firstRootKey);
        final byte[] newRootKey = kdf(ROOT_KEY_LENGTH_BYTES, ROOT_KEY, concatPreviousRootKeyNewK);
        clear(concatPreviousRootKeyNewK);
        return new DoubleRatchet(0, 0, sharedSecret, newRootKey, sender, receiver, next, new HashMap<>());
    }

    private static DoubleRatchet rotate(final Purpose rotate, final int nextI, final int pn, final MixedSharedSecret newSharedSecret,
            final byte[] prevRootKey, final Ratchet sender, final Ratchet receiver,
            final HashMap<Long, MessageKeys> storedKeys) {
        requireLengthExactly(ROOT_KEY_LENGTH_BYTES, prevRootKey);
        assert !allZeroBytes(prevRootKey) : "Expecting random data instead of all zero-bytes. There might be something severely wrong.";
        final byte[] newK = newSharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(prevRootKey, newK);
        final Ratchet nextSender, nextReceiver;
        final Purpose nextRotate;
        switch (rotate) {
        case SENDING:
            nextSender = Ratchet.create(concatPreviousRootKeyNewK);
            nextReceiver = new Ratchet(receiver);
            nextRotate = Purpose.RECEIVING;
            break;
        case RECEIVING:
            nextSender = new Ratchet(sender);
            nextReceiver = Ratchet.create(concatPreviousRootKeyNewK);
            nextRotate = Purpose.SENDING;
            break;
        default:
            throw new UnsupportedOperationException("BUG: unsupported purpose encountered.");
        }
        clear(newK);
        // NOTE: not clearing previous rootKey because we create a new instance without affecting the original instance.
        final byte[] newRootKey = kdf(ROOT_KEY_LENGTH_BYTES, ROOT_KEY, concatPreviousRootKeyNewK);
        clear(concatPreviousRootKeyNewK);
        return new DoubleRatchet(nextI, pn, newSharedSecret, newRootKey, nextSender, nextReceiver, nextRotate,
                storedKeys);
    }

    private DoubleRatchet(final int i, final int pn, final MixedSharedSecret sharedSecret, final byte[] newRootKey,
            final Ratchet sender, final Ratchet receiver, final Purpose next,
            final HashMap<Long, MessageKeys> storedKeys) {
        this.i = i;
        this.pn = pn;
        this.rootKey = requireLengthExactly(ROOT_KEY_LENGTH_BYTES, newRootKey);
        this.sharedSecret = requireNonNull(sharedSecret);
        this.senderRatchet = requireNonNull(sender);
        this.receiverRatchet = requireNonNull(receiver);
        this.nextRotation = requireNonNull(next);
        this.storedKeys = requireNonNull(storedKeys);
    }

    @Override
    public void close() {
        clear(this.rootKey);
        this.sharedSecret.close();
        // TODO ensure that storedKeys are cleaned up.
        // TODO we need to derive MK_MAC keys from storedKeys and reveal those.
        //if (this.storedKeys.size() > 0) {
        //    throw new IllegalStateException("BUG: Stored keys have not been cleaned up and revealed.");
        //}
        if (this.reveals.size() > 0) {
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
    Purpose nextRotation() {
        return this.nextRotation;
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
        return this.senderRatchet.getMessageID();
    }

    /**
     * The receiver message ID ('k')
     *
     * @return Returns message ID.
     */
    int getK() {
        return this.receiverRatchet.getMessageID();
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
    DoubleRatchet rotateSenderKeys() {
        requireNotClosed();
        if (this.nextRotation != Purpose.SENDING) {
            throw new IllegalStateException("Rotation is only allowed after new public key material was received from the other party.");
        }
        // Perform sender key rotation.
        LOGGER.log(FINE, "Rotating root key and sending chain key for ratchet " + this.i);
        final MixedSharedSecret newSharedSecret = this.sharedSecret.rotateOurKeys(this.i % 3 == 0);
        // With the sender keys rotation, we pass on the instances for stored keys and macs-to-reveal, because either
        // the original (non-rotated) Double Ratchet instance or the new instance will persist. Rotating sender keys
        // does not impact either store.
        return rotate(Purpose.SENDING, this.i + 1, this.senderRatchet.getMessageID(), newSharedSecret,
                this.rootKey, this.senderRatchet, this.receiverRatchet, this.storedKeys);
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
                new Object[]{Math.max(0, this.i - 1), this.senderRatchet.getMessageID()});
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
                new Object[]{Math.max(0, this.i - 1), this.senderRatchet.getMessageID()});
        try (MessageKeys keys = this.generateSendingMessageKeys()) {
            return keys.authenticate(dataMessageSectionsContent).authenticator;
        }
    }

    @MustBeClosed
    @Nonnull
    private MessageKeys generateSendingMessageKeys() {
        final byte[] chainkey = this.senderRatchet.getChainKey();
        try {
            return MessageKeys.fromChainkey(chainkey);
        } finally {
            clear(chainkey);
        }
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
                new Object[]{this.i - 1, this.receiverRatchet.getMessageID()});
        final byte[] decrypted;
        try (MessageKeys keys = generateReceivingMessageKeys(ratchetId, messageId)) {
            final byte[] mkMAC = keys.verify(encodedDataMessageSections, authenticator);
            decrypted = keys.decrypt(ciphertext);
            this.reveals.write(mkMAC, 0, mkMAC.length);
        }
        return decrypted;
    }

    /**
     * Acquire the extra symmetric key that corresponds to the next message to be sent.
     * <p>
     * Note that this is the "raw" extra symmetric key. OTRv4 specifies how one can derive additional keys from this
     * "raw" input data. These derivation steps are not performed. (See
     * `OtrCryptoEngine4#deriveExtraSymmetricKey(int, byte[], byte[])`)
     *
     * @return The "raw" extra symmetric key. (User needs to clean up the byte-array after use.)
     */
    @Nonnull
    byte[] extraSymmetricKeySender() {
        requireNotClosed();
        LOGGER.log(FINEST, "Generating extra symmetric keys for encryption of ratchet {0}, message {1}.",
                new Object[] {Math.max(this.i, 0), this.senderRatchet.getMessageID()});
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
     * @throws RotationLimitationException Indicates that we cross a boundary and therefore we cannot fast-forward
     * rotations for the right message keys to be generated, or retrieve message keys previously stored. This is a
     * limitation of the Double Ratchet. (Or due to a malicious message.) Matching message keys cannot be generated.
     */
    @SuppressWarnings("MustBeClosedChecker")
    @MustBeClosed
    private MessageKeys generateReceivingMessageKeys(final int ratchetId, final int messageId)
            throws RotationLimitationException {
        // NOTE: generateReceivingMessageKeys should not make any (persistent) changes, due to the need to have message
        // keys used first to confirm that the message upon which current actions are based, is authentic.
        requireNotClosed();
        final int currentRatchet = Math.max(0, this.i - 1);
        if (ratchetId > currentRatchet) {
            // We should rotate receiving ratchet receiving (public) keys. 
            throw new IllegalArgumentException("BUG: cannot fast-forward receiving message keys into a new ratchet.");
        }
        if (ratchetId < currentRatchet || messageId < this.receiverRatchet.getMessageID()) {
            // Message keys are in ratchet history, so check the store for possible stored keys.
            final MessageKeys keys = this.storedKeys.get((long) ratchetId << 32 | messageId);
            if (keys == null) {
                throw new RotationLimitationException("No message keys stored.");
            }
            // Copy message keys to ensure they are available (and uncleared) if a second request comes in, e.g. the
            // extra symmetric key.
            return keys.copy();
        }
        final byte[] chainkey = this.receiverRatchet.speculate().rotateInto(messageId);
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
     * Confirm the receiving chain key by ensuring we have rotated past the specified message ID: we either rotate up to
     * and over that point, or -- in case of past message IDs -- remove the stored message keys and remain at the
     * current position.
     * <p>
     * NOTE: the rotation is used to confirm the last received message ID by rotating past this point, and establishing
     * this as current progress marker.
     */
    @SuppressWarnings("MustBeClosedChecker")
    void confirmReceivingChainKey(final int ratchetId, final int messageId) {
        final int currentRatchet = Math.max(0, this.i - 1);
        if (ratchetId > currentRatchet) {
            throw new IllegalArgumentException("BUG: Ratcheting is necessary. This should not happen if message keys were previously generated successfully.");
        }
        if (ratchetId < currentRatchet || messageId < this.receiverRatchet.getMessageID()) {
            // If we previously retrieved the keys from the store, clear the keys from the store.
            LOGGER.log(FINER, "Rotate receiver chainkey: clear stored chainkey {0}, {1}",
                    new Object[]{ratchetId, messageId});
            final MessageKeys oldkeys = this.storedKeys.remove((long) ratchetId << 32 | messageId);
            requireNonNull(oldkeys, "BUG: we rotate away from keys that were just used. These should exist in the store.");
            oldkeys.close();
            return;
        }
        // TODO verify that number of messages needing to fast-forward is acceptable. (max_skip in OTRv4 spec)
        while (messageId > this.receiverRatchet.getMessageID()) {
            // Catch up to current message ID, store these message keys for later use as these messages haven't arrived
            // yet.
            LOGGER.log(FINEST, "Fast-forward rotating receiving chain key to catch up with message ID: {0}",
                    new Object[]{messageId});
            // After every successful decryption of a received message, the receiving chain key is also rotated away.
            // This means that the current receiving message ID (`K`) is always a key not used successfully before.
            // (A failed attempt at decrypting a corrupt/malicious message is still possible.)
            this.storedKeys.put((long) currentRatchet << 32 | this.receiverRatchet.getMessageID(),
                    MessageKeys.fromChainkey(this.receiverRatchet.getChainKey()));
            this.receiverRatchet.rotateChainKey();
        }
        if (messageId == this.receiverRatchet.getMessageID()) {
            // Rotate past this message ID, i.e. forget message keys.
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
     * @param nextDH The other party's DH public key.
     * @param pn Number of messages in the previous receiver ratchet (as advertised in a message).
     * @throws OtrCryptoException thrown if provided public keys are illegal.
     */
    DoubleRatchet rotateReceiverKeys(final Point nextECDH, @Nullable final BigInteger nextDH, final int pn)
            throws OtrCryptoException {
        requireNotClosed();
        if (this.nextRotation != Purpose.RECEIVING) {
            throw new IllegalStateException("Sender keys are expected to rotate next. Message violates protocol.");
        }
        final boolean dhratchet = this.i % 3 == 0;
        if (dhratchet == (nextDH == null)) {
            throw new IllegalArgumentException("BUG: nextDH must be provided for 'third brace key' rotations");
        }
        LOGGER.log(FINE, "Rotating root key and receiving chain key for ratchet {0} (nextDH = {1})",
                new Object[]{this.i, nextDH != null});
        if (nextECDH.constantTimeEquals(this.sharedSecret.getTheirECDHPublicKey())
                || (dhratchet && this.sharedSecret.getTheirDHPublicKey().equals(nextDH))) {
            LOGGER.log(FINE, "Skipping rotating receiver keys as ECDH public key is already known.");
            return this;
        }
        // Shallow-copy the `storedKeys` map such that we can add possible new message keys as we fast-foward to the
        // last message sent in this ratchet.
        final HashMap<Long, MessageKeys> newStoredKeys = new HashMap<>(this.storedKeys);
        if (this.receiverRatchet != Ratchet.INITIAL) {
            this.receiverRatchet.speculate().drainInto(newStoredKeys, Math.max(0, this.i - 1), pn);
        }
        final MixedSharedSecret newSharedSecret = this.sharedSecret.rotateTheirKeys(dhratchet, nextECDH, nextDH);
        return rotate(Purpose.RECEIVING, this.i + 1, this.pn, newSharedSecret, this.rootKey, this.senderRatchet,
                this.receiverRatchet, newStoredKeys);
    }

    /**
     * Collect the MAC-keys-to-be-revealed. (And remove them from the internal list to be revealed.)
     * <p>
     * NOTE: this method should only used to acquire the last remaining MAC keys prior to a session end. The general
     * revelation case is facilitated through key rotation, i.e. `rotateSenderKeys()`.
     *
     * @return Returns the remaining MAC keys to reveal.
     */
    @CheckReturnValue
    byte[] collectReveals() {
        requireNotClosed();
        final byte[] revealed = this.reveals.toByteArray();
        this.reveals.reset();
        return revealed;
    }

    /**
     * transferReveals transfers current MAC-keys-to-be-revealed to the provided (presumably next)
     * DoubleRatchet instance, then clears its own `macsToReveal`.
     *
     * @param dst the destination instance
     */
    void transferReveals(final DoubleRatchet dst) {
        requireNotClosed();
        requireEquals(0, this.reveals.size() % MK_MAC_LENGTH_BYTES);
        final byte[] data = this.reveals.toByteArray();
        dst.reveals.write(data, 0, data.length);
        this.reveals.reset();
    }

    private void requireNotClosed() {
        if (this.i < 0) {
            throw new IllegalStateException("Instance was previously closed and cannot be used anymore.");
        }
    }

    enum Purpose {
        SENDING, RECEIVING
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
}

/**
 * Ratchet, the individual ratchet used for either sending or receiving.
 */
final class Ratchet implements AutoCloseable {

    private static final int CHAIN_KEY_LENGTH_BYTES = 64;

    static final Ratchet INITIAL = new Ratchet(new byte[CHAIN_KEY_LENGTH_BYTES]);

    /**
     * The chain key.
     * <p>
     * The key relies on a first key rotation to become initialized.
     */
    private final byte[] chainKey;

    /**
     * Message ID.
     */
    private int messageID = 0;

    /**
     * Create or rotate the ratchet key.
     */
    static Ratchet create(final byte[] concatPreviousRootKeyNewK) {
        return new Ratchet(kdf(CHAIN_KEY_LENGTH_BYTES, CHAIN_KEY, concatPreviousRootKeyNewK));
    }

    Ratchet(final Ratchet original) {
        this.chainKey = requireNonNull(original.chainKey.clone());
        this.messageID = original.messageID;
    }

    private Ratchet(final byte[] chainKey) {
        this.chainKey = requireLengthExactly(CHAIN_KEY_LENGTH_BYTES, chainKey);
    }

    int getMessageID() {
        return this.messageID;
    }

    @Override
    public void close() {
        if (this == INITIAL) {
            // TODO not happy with this construction. Ideally, INITIAL is its own immutable type, but I would like to avoid constructing a type-hierarchy.
            assert allZeroBytes(this.chainKey) : "BUG: dummy value got corrupted.";
            return;
        }
        this.messageID = MIN_VALUE;
        clear(this.chainKey);
    }

    @Nonnull
    Simula speculate() {
        // NOTE: inviting trouble by calling this 'speculate'. Still seems to be the best suitable word to express a
        // temporary projection into the future to acquire the message keys needed to authenticate and decrypt a
        // message, such that we can confirm authenticity.
        requireNotClosed();
        requireNotEquals(INITIAL, this, "BUG: working with initial dummy for ratchet.");
        return new Simula();
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
        requireNotEquals(INITIAL, this, "BUG: working with initial dummy for ratchet.");
        return this.chainKey.clone();
    }

    /**
     * Rotate the chain key.
     * <p>
     * Generate a new chain key based on the old chain key and increment the message ID.
     */
    void rotateChainKey() {
        requireNotClosed();
        requireNotEquals(INITIAL, this, "BUG: working with initial dummy for ratchet.");
        this.messageID += 1;
        kdf(this.chainKey, 0, CHAIN_KEY_LENGTH_BYTES, NEXT_CHAIN_KEY, this.chainKey);
    }

    private void requireNotClosed() {
        if (this.messageID < 0) {
            throw new IllegalStateException("Ratchet instance is already closed.");
        }
    }

    /**
     * Simula simulates a number of chain key rotations. This makes it possible to acquire the right authentication and
     * decryption keys, resp. MK_MAC and MK_ENC, without changing the state yet.
     */
    final class Simula {

        private Simula() {
            // enforce private access to constructor
        }

        /**
         * Rotate the chain key into the chain key for specified message ID.
         * <p>
         * Generate a new chain key based on the old chain key incremented to the message ID.
         *
         * @param targetMessageId fast-forward to the target message ID.
         */
        @Nonnull
        byte[] rotateInto(final int targetMessageId) {
            final byte[] localChainKey = Arrays.copyOf(Ratchet.this.chainKey, CHAIN_KEY_LENGTH_BYTES);
            for (int i = Ratchet.this.messageID; i < targetMessageId; i++) {
                kdf(localChainKey, 0, CHAIN_KEY_LENGTH_BYTES, NEXT_CHAIN_KEY, localChainKey);
            }
            return localChainKey;
        }

        /**
         * Generate and insert message keys into provided store from
         *
         * @param store the skipped message keys store
         * @param ratchetID the current ratchet's ID (`i`)
         * @param messageID the receiver message ID (`k`)
         */
        @SuppressWarnings("MustBeClosedChecker")
        void drainInto(final Map<Long, MessageKeys> store, final int ratchetID, final int messageID) {
            final byte[] localChainKey = Arrays.copyOf(Ratchet.this.chainKey, CHAIN_KEY_LENGTH_BYTES);
            for (int k = Ratchet.this.messageID; k < messageID; k++) {
                store.put((long) ratchetID << 32 | k, MessageKeys.fromChainkey(localChainKey));
                kdf(localChainKey, 0, CHAIN_KEY_LENGTH_BYTES, NEXT_CHAIN_KEY, localChainKey);
            }
        }
    }
}
