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
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthIMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.IdentityMessages;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;
import net.java.otr4j.session.state.DoubleRatchet.Purpose;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FIRST_ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ROOT_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.io.ErrorMessage.ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_NOT_IN_PRIVATE_STATE;
import static net.java.otr4j.messages.AuthRMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_I;
import static net.java.otr4j.messages.MysteriousT4.encode;

/**
 * OTRv4 AKE state AWAITING_AUTH_R.
 */
// TODO check OTRv4 spec for instructions on temporarily storing recently received messages while negotiating.
final class StateAwaitingAuthR extends AbstractCommonState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingAuthR.class.getName());

    private static final SessionStatus STATUS = SessionStatus.PLAINTEXT;

    /**
     * The identity message previously sent.
     */
    private final IdentityMessage previousMessage;

    /**
     * Our client profile payload.
     */
    private final ClientProfilePayload profilePayload;

    /**
     * Our ECDH key pair 'Y', 'y'.
     */
    private final ECDHKeyPair y;

    /**
     * Our DH key pair 'B', 'b'.
     */
    private final DHKeyPair b;

    private final ECDHKeyPair firstECDHKeyPair;

    private final DHKeyPair firstDHKeyPair;

    StateAwaitingAuthR(final AuthState authState, final ECDHKeyPair y, final DHKeyPair b,
            final ECDHKeyPair firstECDHKeyPair, final DHKeyPair firstDHKeyPair,
            final ClientProfilePayload profilePayload, final IdentityMessage previousMessage) {
        super(authState);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.firstECDHKeyPair = requireNonNull(firstECDHKeyPair);
        this.firstDHKeyPair = requireNonNull(firstDHKeyPair);
        this.profilePayload = requireNonNull(profilePayload);
        this.previousMessage = requireNonNull(previousMessage);
    }

    @Override
    public int getVersion() {
        return Session.Version.FOUR;
    }

    @Nonnull
    @Override
    public SessionStatus getStatus() {
        return STATUS;
    }

    @Nonnull
    @Override
    public RemoteInfo getRemoteInfo() throws IncorrectStateException {
        throw new IncorrectStateException("No OTR session is established yet.");
    }

    @Nonnull
    @Override
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available until encrypted session is fully established.");
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available until encrypted session is fully established.");
    }

    @Nonnull
    @Override
    public Result handlePlainTextMessage(final Context context, final PlainTextMessage message) {
        return new Result(STATUS, false, false, message.getCleanText());
    }

    @Nonnull
    @Override
    public Result handleEncodedMessage(final Context context, final EncodedMessage message) throws ProtocolException, OtrException {
        switch (message.version) {
        case Session.Version.ONE:
            LOGGER.log(INFO, "Encountered message for protocol version 1. Ignoring message.");
            return new Result(STATUS, true, false, null);
        case Session.Version.TWO:
        case Session.Version.THREE:
            LOGGER.log(INFO, "Encountered message for lower protocol version: {0}. Ignoring message.",
                    new Object[]{message.version});
            return new Result(STATUS, true, false, null);
        case Session.Version.FOUR:
            return handleEncodedMessage4(context, message);
        default:
            throw new UnsupportedOperationException("BUG: Unsupported protocol version: " + message.version);
        }
    }

    @Override
    void handleAKEMessage(final Context context, final AbstractEncodedMessage message) throws OtrException {
        if (message instanceof IdentityMessage) {
            try {
                handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(INFO, "Failed to process Identity message.", e);
            }
            return;
        }
        if (message instanceof AuthRMessage) {
            try {
                handleAuthRMessage(context, (AuthRMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(WARNING, "Failed to process Auth-R message.", e);
            }
            return;
        }
        // OTR: "Ignore the message."
        LOGGER.log(INFO, "We only expect to receive an Identity message or an Auth-R message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
    }

    @Override
    void handleIdentityMessage(final Context context, final IdentityMessage message) throws OtrException {
        final ClientProfile theirProfile = message.clientProfile.validate();
        IdentityMessages.validate(message, theirProfile);
        if (this.previousMessage.b.compareTo(message.b) > 0) {
            // No state change necessary, we assume that by resending other party will still follow existing protocol
            // execution.
            context.injectMessage(this.previousMessage);
            return;
        }
        // Clear old key material, then start a new DAKE from scratch with different keys.
        this.b.close();
        this.y.close();
        // Pretend we are still in initial state and handle Identity message accordingly.
        super.handleIdentityMessage(context, message);
    }

    private void handleAuthRMessage(final Context context, final AuthRMessage message) throws OtrException {
        final SessionID sessionID = context.getSessionID();
        final EdDSAKeyPair ourLongTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        // Validate received Auth-R message.
        final ClientProfile ourClientProfile = this.profilePayload.validate();
        final ClientProfile theirClientProfile = message.clientProfile.validate();
        validate(message, this.profilePayload, ourClientProfile, theirClientProfile, sessionID.getUserID(),
                sessionID.getAccountID(), this.y.publicKey(), this.b.publicKey(),
                this.firstECDHKeyPair.publicKey(), this.firstDHKeyPair.publicKey());
        final SecureRandom secureRandom = context.secureRandom();
        // Prepare Auth-I message to be sent.
        final InstanceTag senderTag = context.getSenderInstanceTag();
        final InstanceTag receiverTag = context.getReceiverInstanceTag();
        final byte[] t = encode(AUTH_I, message.clientProfile, this.profilePayload, message.x,
                this.y.publicKey(), message.a, this.b.publicKey(),
                this.firstECDHKeyPair.publicKey(), this.firstDHKeyPair.publicKey(),
                message.firstECDHPublicKey, message.firstDHPublicKey, senderTag, receiverTag,
                sessionID.getAccountID(), sessionID.getUserID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(secureRandom, ourLongTermKeyPair,
                ourLongTermKeyPair.getPublicKey(), theirClientProfile.getForgingKey(), message.x, t);
        context.injectMessage(new AuthIMessage(senderTag, receiverTag, sigma));
        // Calculate mixed shared secret and SSID.
        final byte[] k;
        final byte[] ssid;
        try (MixedSharedSecret sharedSecret = new MixedSharedSecret(secureRandom, this.y, this.b, message.x, message.a)) {
            k = sharedSecret.getK();
            ssid = sharedSecret.generateSSID();
        }
        // Initialize Double Ratchet.
        final MixedSharedSecret firstRatchetSecret = new MixedSharedSecret(secureRandom, this.firstECDHKeyPair,
                this.firstDHKeyPair, message.firstECDHPublicKey, message.firstDHPublicKey);
        final DoubleRatchet ratchet;
        try (DoubleRatchet initial = DoubleRatchet.initialize(Purpose.RECEIVING, firstRatchetSecret,
                kdf(ROOT_KEY_LENGTH_BYTES, FIRST_ROOT_KEY, k))) {
            ratchet = initial.rotateSenderKeys();
        }
        secure(context, ssid, ratchet, ourClientProfile.getLongTermPublicKey(), ourClientProfile.getForgingKey(),
                theirClientProfile);
    }

    @Nonnull
    @Override
    Result handleDataMessage(final Context context, final DataMessage message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv3 data message in state WAITING_AUTH_I. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return new Result(STATUS, true, false, null);
    }

    @Nonnull
    @Override
    Result handleDataMessage(final Context context, final DataMessage4 message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv4 data message in state WAITING_AUTH_I. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return new Result(STATUS, true, false, null);
    }

    @Override
    public void end(final Context context) {
        this.b.close();
        this.y.close();
        this.firstDHKeyPair.close();
        this.firstECDHKeyPair.close();
        context.transition(this, new StatePlaintext(getAuthState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy (i.e. we need to destroy different material for different transitions)
    }
}
