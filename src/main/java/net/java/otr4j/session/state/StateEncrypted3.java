/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.Event;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.EncryptedMessage.Content;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.io.QueryMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.MysteriousT;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.smp.SMException;
import net.java.otr4j.session.smp.SmpTlvHandler;
import net.java.otr4j.session.state.SessionKeyManager.SessionKeyUnavailableException;
import net.java.otr4j.util.ByteArrays;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Collections.singletonList;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.OtrEngineHosts.onEvent;
import static net.java.otr4j.api.OtrPolicys.allowedVersions;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesDecrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesEncrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha1Hmac;
import static net.java.otr4j.crypto.OtrCryptoEngine4.EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES;
import static net.java.otr4j.io.EncryptedMessage.extractContents;
import static net.java.otr4j.io.ErrorMessage.ERROR_1_MESSAGE_UNREADABLE_MESSAGE;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.session.smp.DSAPublicKeys.fingerprint;
import static net.java.otr4j.session.smp.SmpTlvHandler.smpPayload;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * Message state in case an encrypted session is established.
 * <p>
 * This message state is package-private as we only allow transitioning to this
 * state through the initial PLAINTEXT state.
 *
 * @author Danny van Heumen
 */
// TODO write additional unit tests for StateEncrypted3
final class StateEncrypted3 extends AbstractCommonState implements StateEncrypted {

    private static final SessionStatus STATUS = SessionStatus.ENCRYPTED;

    /**
     * TLV 8 notifies the recipient to use the extra symmetric key to set up an
     * out-of-band encrypted connection.
     * <p>
     * Payload:
     *  - 4-byte indication of what to use it for, e.g. file transfer, voice
     *    encryption, ...
     *  - undefined, free for use. Subsequent data might be the file name of
     *    your confidential file transfer.
     * <p>
     * WARNING! You should NEVER send the extra symmetric key as payload inside
     * the TLV record. The recipient can already generate the extra symmetric
     * key.
     */
    private static final int USE_EXTRA_SYMMETRIC_KEY = 0x0008;

    /**
     * Active version of the protocol in use in this encrypted session.
     */
    private final int protocolVersion;

    @SuppressWarnings("PMD.LoggerIsNotStaticFinal")
    private final Logger logger;

    /**
     * The Socialist Millionaire Protocol handler.
     */
    @Nonnull
    private final SmpTlvHandler smpTlvHandler;

    /**
     * Long-term remote public key.
     */
    @Nonnull
    private final DSAPublicKey remotePublicKey;

    /**
     * Manager for session keys that are used during encrypted message state.
     */
    private final SessionKeyManager sessionKeyManager;

    private long lastMessageSentTimestamp = System.nanoTime();

    StateEncrypted3(final Context context, final AuthState state, final SecurityParameters params)
            throws OtrCryptoException {
        super(state);
        final SessionID sessionID = context.getSessionID();
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.protocolVersion = params.getVersion();
        this.smpTlvHandler = new SmpTlvHandler(context.secureRandom(), sessionID,
                fingerprint(context.getLocalKeyPair().getPublic()), fingerprint(params.getRemoteLongTermPublicKey()),
                context.getReceiverInstanceTag(), context.getHost(), params.getS());
        this.remotePublicKey = params.getRemoteLongTermPublicKey();
        this.sessionKeyManager = new SessionKeyManager(context.secureRandom(), params.getLocalDHKeyPair(),
                params.getRemoteDHPublicKey());
    }

    @Nonnull
    @Override
    public Result handlePlainTextMessage(final Context context, final PlainTextMessage message) {
        // Display the message to the user, but warn him that the message was received unencrypted.
        onEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(),
                Event.UNENCRYPTED_MESSAGE_RECEIVED, message.getCleanText());
        // TODO what does this mean exactly: we have received a plaintext message under an ENCRYPTED context.
        return new Result(STATUS, false, false, message.getCleanText());
    }

    @Override
    public int getVersion() {
        return this.protocolVersion;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return STATUS;
    }

    @Nonnull
    @Override
    public RemoteInfo getRemoteInfo() {
        return new RemoteInfo(Version.THREE, this.remotePublicKey, null);
    }

    @Override
    @Nonnull
    public SmpTlvHandler getSmpHandler() {
        return this.smpTlvHandler;
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() {
        if (this.protocolVersion == Version.TWO) {
            throw new UnsupportedOperationException("An OTR version 2 session was negotiated. The Extra Symmetric Key is not available in this version of the protocol.");
        }
        return this.sessionKeyManager.extraSymmetricKey();
    }

    @Nonnull
    @Override
    public Result handleEncodedMessage(final Context context, final EncodedMessage message) throws ProtocolException, OtrException {
        switch (message.version) {
        case Session.Version.ONE:
            this.logger.log(INFO, "Encountered message for protocol version 1. Ignoring message.");
            return new Result(STATUS, true, false, null);
        case Session.Version.TWO:
        case Session.Version.THREE:
            return handleEncodedMessage3(context, message);
        case Session.Version.FOUR:
            this.logger.log(INFO, "Encountered message for protocol version 4. Ignoring because OTRv3 in-progress.",
                    new Object[]{message.version});
            return new Result(STATUS, true, false, null);
        default:
            throw new UnsupportedOperationException("BUG: Unsupported protocol version: " + message.version);
        }
    }

    @Override
    void handleAKEMessage(final Context context, final AbstractEncodedMessage message) {
        this.logger.log(FINE, "Ignoring OTRv4 DAKE message as we are in OTRv3 encrypted message state.");
    }

    @Override
    @Nonnull
    @SuppressWarnings("PMD.CognitiveComplexity")
    Result handleDataMessage(final Context context, final DataMessage message) throws OtrException, ProtocolException {
        this.logger.finest("Message state is ENCRYPTED. Trying to decrypt message.");
        // Find matching session keys.
        final SessionKey matchingKeys;
        try {
            matchingKeys = this.sessionKeyManager.get(message.recipientKeyID, message.senderKeyID);
        } catch (final SessionKeyUnavailableException ex) {
            this.logger.finest("No matching keys found.");
            handleUnreadableMessage(context, message, "", ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
            return new Result(STATUS, true, false, null);
        }

        // Verify received MAC with a locally calculated MAC.
        this.logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");

        final byte[] computedMAC = sha1Hmac(encode(message.getT()), matchingKeys.receivingMAC());
        if (!constantTimeEquals(computedMAC, message.mac)) {
            this.logger.finest("MAC verification failed, ignoring message.");
            handleUnreadableMessage(context, message, "", ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
            return new Result(STATUS, true, false, null);
        }

        this.logger.finest("Computed HmacSHA1 value matches sent one.");

        // Mark this MAC key as old to be revealed.
        matchingKeys.markUsed();
        final byte[] dmc;
        try {
            final byte[] lengthenedReceivingCtr = matchingKeys.verifyReceivingCtr(message.ctr);
            dmc = aesDecrypt(matchingKeys.receivingAESKey(), lengthenedReceivingCtr, message.encryptedMessage);
        } catch (final SessionKey.ReceivingCounterValidationFailed ex) {
            this.logger.log(Level.WARNING, "Receiving ctr value failed validation, ignoring message: {0}", ex.getMessage());
            // FIXME should we inject an ErrorMessage because of this? Seems better to just ignore.
            context.injectMessage(new ErrorMessage("", "Message's counter value failed validation."));
            return new Result(STATUS, true, false, null);
        }

        // Rotate keys if necessary.
        final SessionKey mostRecent = this.sessionKeyManager.getMostRecentSessionKeys();
        if (mostRecent.getLocalKeyID() == message.recipientKeyID) {
            this.sessionKeyManager.rotateLocalKeys();
        }
        if (mostRecent.getRemoteKeyID() == message.senderKeyID) {
            this.sessionKeyManager.rotateRemoteKeys(message.nextDH);
        }

        // Extract and process TLVs.
        final Content content = extractContents(dmc);
        for (final TLV tlv : content.tlvs) {
            this.logger.log(FINE, "Received TLV type {0}", tlv.type);
            if (smpPayload(tlv)) {
                try {
                    final TLV response = this.smpTlvHandler.process(tlv);
                    if (response != null) {
                        context.injectMessage(transformSending(context, "", singletonList(response), FLAG_IGNORE_UNREADABLE));
                    }
                } catch (final SMException e) {
                    this.logger.log(Level.WARNING, "Illegal, bad or corrupt SMP TLV encountered. Stopped processing. This may indicate a bad implementation of OTR at the other party.",
                            e);
                }
                continue;
            }
            switch (tlv.type) {
            case TLV.PADDING: // TLV0
                // nothing to do here, just ignore the padding
                break;
            case TLV.DISCONNECTED: // TLV1
                if (!content.message.isEmpty()) {
                    this.logger.warning("Expected other party to send TLV type 1 with empty human-readable message.");
                }
                context.transition(this, new StateFinished(getAuthState()));
                break;
            case USE_EXTRA_SYMMETRIC_KEY:
                if (tlv.value.length < EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES) {
                    throw new ProtocolException("OTR protocol specification requires at least 4 bytes, indicating the purpose for the extra symmetric key.");
                }
                final byte[] key = matchingKeys.extraSymmetricKey();
                if (constantTimeEquals(key, tlv.value)) {
                    this.logger.log(WARNING, "Other party sent Extra Symmetric Key in the TLV payload. This is incorrect use of the Extra Symmetric Key and exposes a secret value unnecessarily.");
                }
                final byte[] eskContext = ByteArrays.cloneRange(tlv.value, 0, 4);
                final byte[] eskValue = ByteArrays.cloneRange(tlv.value, 4, tlv.value.length - 4);
                onEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(),
                        Event.EXTRA_SYMMETRIC_KEY_DISCOVERED, new Event.ExtraSymmetricKey(key, eskContext, eskValue));
                break;
            default:
                this.logger.log(INFO, "Unsupported TLV #{0} received. Ignoring.", tlv.type);
                break;
            }
        }
        return new Result(STATUS, false, true, content.message.isEmpty() ? null : content.message);
    }

    @Nonnull
    @Override
    Result handleDataMessage(final Context context, final DataMessage4 message) {
        throw new IllegalStateException("BUG: OTRv2/OTRv3 encrypted message state does not handle OTRv4 data messages.");
    }

    @Override
    public void handleErrorMessage(final Context context, final ErrorMessage errorMessage) throws OtrException {
        super.handleErrorMessage(context, errorMessage);
        final OtrPolicy policy = context.getSessionPolicy();
        if (!policy.viable() || !policy.isErrorStartAKE()) {
            return;
        }
        // Re-negotiate if we got an error and we are in ENCRYPTED message state
        this.logger.finest("Error message starts AKE.");
        final Set<Integer> versions = allowedVersions(policy);
        this.logger.finest("Sending Query");
        context.injectMessage(new QueryMessage(versions));
    }

    @Override
    @Nonnull
    public DataMessage transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) {
        final SessionID sessionID = context.getSessionID();
        this.logger.log(FINEST, "{0} sends an encrypted message to {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        final byte[] data = new OtrOutputStream().writeMessage(msgText).writeByte(0).writeTLV(tlvs).toByteArray();

        // Get encryption keys.
        final SessionKey encryptionKeys = this.sessionKeyManager.getEncryptionSessionKeys();
        final int senderKeyID = encryptionKeys.getLocalKeyID();
        final int recipientKeyID = encryptionKeys.getRemoteKeyID();

        // Increment CTR.
        final byte[] ctr = encryptionKeys.acquireSendingCtr();

        // Encrypt message.
        this.logger.log(FINEST, "Encrypting message with keyids (localKeyID, remoteKeyID) = ({0}, {1})",
                new Object[]{senderKeyID, recipientKeyID});
        final byte[] encryptedMsg = aesEncrypt(encryptionKeys.sendingAESKey(), ctr, data);

        // Get most recent keys to get the next D-H public key.
        final SessionKey mostRecentKeys = this.sessionKeyManager.getMostRecentSessionKeys();
        final DHPublicKey nextDH = mostRecentKeys.getLocalKeyPair().getPublic();

        // Calculate T.
        final MysteriousT t = new MysteriousT(this.protocolVersion, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), flags, senderKeyID, recipientKeyID, nextDH, ctr, encryptedMsg);

        // Calculate T hash.
        final byte[] sendingMACKey = encryptionKeys.sendingMAC();

        this.logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");
        final byte[] mac = sha1Hmac(encode(t), sendingMACKey);

        // Get old MAC keys to be revealed.
        final byte[] oldKeys = this.sessionKeyManager.collectOldMacKeys();
        final DataMessage message = new DataMessage(t, mac, oldKeys, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag());
        this.lastMessageSentTimestamp = System.nanoTime();
        return message;
    }

    @Override
    public void end(final Context context) throws OtrException {
        // The message carrying TLV 1 (Disconnect) is supposed to contain remaining MAC keys. However, as part of
        // sending the data message, we already include remaining MAC keys as part of sending the Data message.
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, TLV.EMPTY_BODY);
        final AbstractEncodedMessage m = transformSending(context, "", singletonList(disconnectTlv),
                FLAG_IGNORE_UNREADABLE);
        try {
            context.injectMessage(m);
        } finally {
            // Transitioning to PLAINTEXT state should not depend on host. Ensure we transition to PLAINTEXT even if we
            // have problems injecting the message into the transport.
            context.transition(this, new StatePlaintext(getAuthState()));
        }
    }

    @Override
    public void destroy() {
        this.smpTlvHandler.close();
        this.sessionKeyManager.close();
    }

    @Override
    public long getLastMessageSentTimestamp() {
        return this.lastMessageSentTimestamp;
    }
}
