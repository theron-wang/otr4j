/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncryptedMessage.Content;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.smpv4.SMP;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.util.logging.Logger;

import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.OtrEngineHosts.extraSymmetricKeyDiscovered;
import static net.java.otr4j.api.OtrEngineHosts.unencryptedMessageReceived;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.TLV.DISCONNECTED;
import static net.java.otr4j.api.TLV.PADDING;
import static net.java.otr4j.io.EncryptedMessage.extractContents;
import static net.java.otr4j.io.ErrorMessage.ERROR_1_MESSAGE_UNREADABLE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_UNREADABLE_MESSAGE;
import static net.java.otr4j.messages.DataMessage4s.encodeDataMessageSections;
import static net.java.otr4j.messages.DataMessage4s.validate;
import static net.java.otr4j.session.smpv4.SMP.smpPayload;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.clear;
import static net.java.otr4j.util.ByteArrays.concatenate;

/**
 * The OTRv4 ENCRYPTED_MESSAGES state.
 */
// TODO write additional unit tests for StateEncrypted4
// TODO decide whether or not we can drop the AuthState instance. Relies on fact that we need to know up to what point we should handle OTRv2/3 AKE messages.
final class StateEncrypted4 extends AbstractCommonState implements StateEncrypted {

    private static final int VERSION = FOUR;

    /**
     * Note that in OTRv4 the TLV type for the extra symmetric key is 0x7.
     */
    private static final int EXTRA_SYMMETRIC_KEY = 0x7;

    private static final int EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES = 4;

    @SuppressWarnings("PMD.LoggerIsNotStaticFinal")
    private final Logger logger;

    private DoubleRatchet ratchet;

    private final SMP smp;

    private long lastMessageSentTimestamp = System.nanoTime();
    
    private final RemoteInfo remoteinfo;

    StateEncrypted4(final Context context, final byte[] ssid, final DoubleRatchet ratchet,
            final Point ourLongTermPublicKey, final Point ourForgingKey, final ClientProfile theirProfile,
             final AuthState authState) {
        super(authState);
        final SessionID sessionID = context.getSessionID();
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.ratchet = requireNonNull(ratchet);
        this.smp = new SMP(context.secureRandom(), context.getHost(), sessionID, ssid, ourLongTermPublicKey,
                ourForgingKey, theirProfile.getLongTermPublicKey(), theirProfile.getForgingKey(),
                context.getReceiverInstanceTag());
        this.remoteinfo = new RemoteInfo(FOUR, theirProfile.getDsaPublicKey(), theirProfile);
    }

    @Nonnull
    @Override
    public String handlePlainTextMessage(final Context context, final PlainTextMessage message) {
        // Display the message to the user, but warn him that the message was received unencrypted.
        unencryptedMessageReceived(context.getHost(), context.getSessionID(), message.getCleanText());
        return message.getCleanText();
    }

    @Override
    public int getVersion() {
        return VERSION;
    }

    @Nonnull
    @Override
    public SessionStatus getStatus() {
        return SessionStatus.ENCRYPTED;
    }

    @Nonnull
    @Override
    public RemoteInfo getRemoteInfo() {
        return this.remoteinfo;
    }

    /**
     * The extra symmetric key is the "raw" key of the Sender. It does not perform the additional multi-key-derivations
     * that are described in the OTRv4 specification in case of multiple TLV 7 payloads using index and payload context
     * (first 4 bytes).
     * <p>
     * The acquired extra symmetric key is the key that corresponds to the next message that is sent.
     * <p>
     * Note: the user is responsible for cleaning up the extra symmetric key material after use.
     * <p>
     * Note: for receiving keys we currently automatically calculate the derived keys, so the sending user is expected
     * to do the same. You can use {@link net.java.otr4j.crypto.OtrCryptoEngine4#deriveExtraSymmetricKey(int, byte[], byte[])}
     * for this.
     * <p>
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public byte[] getExtraSymmetricKey() {
        return this.ratchet.extraSymmetricKeySender();
    }

    @Nonnull
    @Override
    public DataMessage4 transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) {
        return transformSending(context, msgText, tlvs, flags, new byte[0]);
    }

    @Nonnull
    private DataMessage4 transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags, final byte[] providedMACsToReveal) {
        assert providedMACsToReveal.length == 0 || !allZeroBytes(providedMACsToReveal)
                : "BUG: expected providedMACsToReveal to contains some non-zero values.";
        // Perform ratchet if necessary, possibly collecting MAC codes to reveal.
        final byte[] collectedMACs;
        if (this.ratchet.nextRotation() == DoubleRatchet.Purpose.SENDING) {
            final byte[] revealedMacs;
            try (DoubleRatchet previous = this.ratchet) {
                this.ratchet = this.ratchet.rotateSenderKeys();
                revealedMacs = previous.collectRemainingMACsToReveal();
            }
            this.logger.log(FINEST, "Sender keys rotated. revealed MACs size: {0}.",
                    new Object[]{revealedMacs.length});
            collectedMACs = concatenate(providedMACsToReveal, revealedMacs);
        } else {
            this.logger.log(FINEST, "Sender keys rotation is not needed.");
            collectedMACs = providedMACsToReveal;
        }
        // Construct data message.
        final byte[] msgBytes = new OtrOutputStream().writeMessage(msgText).writeByte(0).writeTLV(tlvs).toByteArray();
        final byte[] ciphertext = this.ratchet.encrypt(msgBytes);
        // "When sending a data message in the same DH Ratchet: Set `i - 1` as the Data message's ratchet id. (except
        // for when immediately sending data messages after receiving a Auth-I message. In that it case it should be Set
        // `i` as the Data message's ratchet id)."
        final int ratchetId = Math.max(0, this.ratchet.getI() - 1);
        final int messageId = this.ratchet.getJ();
        final BigInteger dhPublicKey = ratchetId % 3 == 0 ? this.ratchet.getDHPublicKey() : null;
        // We intentionally set the authenticator to `new byte[64]` (all zero-bytes), such that we can calculate the
        // corresponding authenticator value. Then we construct a new DataMessage4 and substitute the real authenticator
        // for the dummy.
        final DataMessage4 unauthenticated = new DataMessage4(context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), flags, this.ratchet.getPn(), ratchetId, messageId,
                this.ratchet.getECDHPublicKey(), dhPublicKey, ciphertext, new byte[64], collectedMACs);
        final byte[] authenticator = this.ratchet.authenticate(encodeDataMessageSections(unauthenticated));
        // TODO we rotate away, so we need to acquire the extra symmetric key for this message ID now or never.
        this.ratchet.rotateSendingChainKey();
        final DataMessage4 message = new DataMessage4(unauthenticated, authenticator);
        this.lastMessageSentTimestamp = System.nanoTime();
        return message;
    }

    @Override
    void handleAKEMessage(final Context context, final AbstractEncodedMessage message) throws OtrException {
        if (message instanceof IdentityMessage) {
            try {
                handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final ValidationException e) {
                this.logger.log(INFO, "Failed to process Identity message.", e);
            }
            return;
        }
        this.logger.log(INFO, "We only expect to receive an Identity message. Ignoring message with messagetype: {0}",
                message.getType());
    }

    @Nullable
    @Override
    String handleDataMessage(final Context context, final DataMessage message) {
        throw new IllegalStateException("BUG: OTRv4 encrypted message state does not allow OTRv2/OTRv3 data messages.");
    }

    @Nullable
    @Override
    @SuppressWarnings("PMD.CognitiveComplexity")
    String handleDataMessage(final Context context, final DataMessage4 message) throws OtrException, ProtocolException {
        validate(message);
        if (message.i < this.ratchet.getI() - 1) {
            // FIXME this can be assumed to work: simply pass through to Double Ratchet, look in stored keys map and return something if available.
            // Ratchet ID < our current ratchet ID. This is technically impossible, so should not be supported.
            throw new ProtocolException("The double ratchet does not allow for first messages of previous ratchet ID to arrive at a later time. This is an illegal message.");
        }
        if (message.i > this.ratchet.getI()) {
            this.logger.log(WARNING, "Received message is for a future ratchet ID: message must be malicious. (Current ratchet: {0}, message ratchet: {1})",
                    new Object[]{this.ratchet.getI(), message.i});
            throw new ProtocolException("Received message is for a future ratchet; must be malicious.");
        }
        final DoubleRatchet provisional;
        if (message.i == this.ratchet.getI()) {
            // If any message in a new ratchet is received, a new ratchet key has been received, any message keys
            // corresponding to skipped messages from the previous receiving ratchet are stored. A new DH ratchet is
            // performed.
            if (this.ratchet.nextRotation() != DoubleRatchet.Purpose.RECEIVING) {
                throw new ProtocolException("Message in next ratchet received before sending keys were rotated. Message violates protocol; probably malicious.");
            }
            // NOTE: with each message in a new ratchet, we receive new public keys. To acquire the authentication and
            // decryption keys, we need to incorporate these public keys in the ratchet. However, this means we must
            // work with unauthenticated data. Therefore, the ratchet constructs a new instance upon each rotation. We
            // work with the new ratchet instance provisionally, until we have authenticated and decrypted the message.
            // Only after successfully processing the message, do we transition to the new ratchet instance.
            provisional = this.ratchet.rotateReceiverKeys(message.ecdhPublicKey, message.dhPublicKey, message.pn);
        } else {
            provisional = this.ratchet;
        }
        // If the encrypted message corresponds to an stored message key corresponding to an skipped message, the
        // message is verified and decrypted with that key which is deleted from the storage.
        // If a new message from the current receiving ratchet is received, any message keys corresponding to skipped
        // messages from the same ratchet are stored, and a symmetric-key ratchet is performed to derive the current
        // message key and the next receiving chain key. The message is then verified and decrypted.
        final byte[] decrypted;
        final byte[] extraSymmetricKey;
        try {
            decrypted = provisional.decrypt(message.i, message.j, encodeDataMessageSections(message),
                    message.authenticator, message.ciphertext);
            extraSymmetricKey = provisional.extraSymmetricKeyReceiver(message.i, message.j);
        } catch (final RotationLimitationException e) {
            // TODO does RotationLimitationException still have the same meanings as described in log message below?
            this.logger.log(INFO, "Message received that is part of next ratchet. As we do not have the public keys for that ratchet yet, the message cannot be decrypted. This message is now lost.");
            handleUnreadableMessage(context, message, ERROR_ID_UNREADABLE_MESSAGE, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
            return null;
        } catch (final OtrCryptoException e) {
            // TODO should we signal unreadable message if malicious? How to distinguish/decide?
            this.logger.log(INFO, "Received message fails verification. Rejecting the message.");
            handleUnreadableMessage(context, message, ERROR_ID_UNREADABLE_MESSAGE, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
            return null;
        }
        // Now that we successfully passed authentication and decryption, we know that the message was authentic.
        // Therefore, any new key material we might have received is authentic, and the message keys we used were used
        // and subsequently discarded correctly. At this point, malicious messages should not be able to have a lasting
        // impact, while authentic messages correctly progress the Double Ratchet.
        if (provisional != this.ratchet) {
            this.ratchet.transferRemainingMACsToReveal(provisional);
            this.ratchet.close();
            this.ratchet = provisional;
        }
        this.ratchet.confirmReceivingChainKey(message.i, message.j);
        // Process decrypted message contents. Extract and process TLVs. Possibly reply, e.g. SMP, disconnect.
        final Content content = extractContents(decrypted);
        for (final TLV tlv : content.tlvs) {
            this.logger.log(FINE, "Received TLV type {0}", tlv.type);
            if (smpPayload(tlv)) {
                if ((message.flags & FLAG_IGNORE_UNREADABLE) != FLAG_IGNORE_UNREADABLE) {
                    // Detect improvements for protocol implementation of remote party.
                    this.logger.log(WARNING, "Other party is using a faulty OTR client: all SMP messages are expected to have the IGNORE_UNREADABLE flag set.");
                }
                try {
                    final TLV response = this.smp.process(tlv);
                    if (response != null) {
                        context.injectMessage(transformSending(context, "", singletonList(response), FLAG_IGNORE_UNREADABLE));
                    }
                } catch (final ProtocolException | OtrCryptoException e) {
                    this.logger.log(WARNING, "Illegal, bad or corrupt SMP TLV encountered. Stopped processing. This may indicate a bad implementation of OTR at the other party.", e);
                }
                continue;
            }
            switch (tlv.type) {
            case PADDING:
                // nothing to do here, just ignore the padding
                break;
            case DISCONNECTED:
                if ((message.flags & FLAG_IGNORE_UNREADABLE) != FLAG_IGNORE_UNREADABLE) {
                    this.logger.log(WARNING, "Other party is using a faulty OTR client: DISCONNECT messages are expected to have the IGNORE_UNREADABLE flag set.");
                }
                if (!content.message.isEmpty()) {
                    this.logger.warning("Expected other party to send TLV type 1 with empty human-readable message.");
                }
                // TODO this was documented, but what was the rationale to sometimes forget MACs that we should reveal?
                // FIXME another part of the spec says that we reveal MACs in Type 1 TLV too.
                this.ratchet.forgetRemainingMACsToReveal();
                context.transition(this, new StateFinished(getAuthState()));
                break;
            case EXTRA_SYMMETRIC_KEY:
                if (tlv.value.length < EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES) {
                    throw new OtrException("TLV value should contain at least 4 bytes of context identifier.");
                }
                extraSymmetricKeyDiscovered(context.getHost(), context.getSessionID(), content.message,
                        extraSymmetricKey.clone(), tlv.value);
                break;
            default:
                this.logger.log(INFO, "Unsupported TLV #{0} received. Ignoring.", tlv.type);
                break;
            }
        }
        clear(extraSymmetricKey);
        return content.message.length() > 0 ? content.message : null;
    }

    @Nonnull
    @Override
    public SMP getSmpHandler() {
        return this.smp;
    }

    @Override
    public void end(final Context context) throws OtrException {
        // Note: although we send a TLV 1 (DISCONNECT) here, we should not reveal remaining MACs.
        final TLV disconnectTlv = new TLV(DISCONNECTED, new byte[0]);
        final AbstractEncodedMessage m = transformSending(context, "", singletonList(disconnectTlv), FLAG_IGNORE_UNREADABLE);
        try {
            context.injectMessage(m);
        } finally {
            // Transitioning to PLAINTEXT state should not depend on host. Ensure we transition to PLAINTEXT even if we
            // have problems injecting the message into the transport.
            context.transition(this, new StatePlaintext(getAuthState()));
        }
    }

    @Override
    public void expire(final Context context) throws OtrException {
        final TLV disconnectTlv = new TLV(DISCONNECTED, TLV.EMPTY_BODY);
        final DataMessage4 m = transformSending(context, "", singleton(disconnectTlv), FLAG_IGNORE_UNREADABLE,
                this.ratchet.collectRemainingMACsToReveal());
        try {
            context.injectMessage(m);
        } finally {
            context.transition(this, new StateFinished(getAuthState()));
        }
    }

    @Override
    public void destroy() {
        this.ratchet.close();
        this.smp.close();
    }

    @Override
    public long getLastActivityTimestamp() {
        return this.ratchet.getLastRotation();
    }

    @Override
    public long getLastMessageSentTimestamp() {
        return this.lastMessageSentTimestamp;
    }
}
