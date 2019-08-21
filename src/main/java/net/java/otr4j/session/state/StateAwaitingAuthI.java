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
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FIRST_ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ROOT_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.io.ErrorMessage.ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_NOT_IN_PRIVATE_STATE;
import static net.java.otr4j.messages.AuthIMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;
import static net.java.otr4j.session.state.DoubleRatchet.Role.ALICE;
import static org.bouncycastle.util.Arrays.clear;

/**
 * The state AWAITING_AUTH_I.
 *
 * This is a state in which Alice will be while awaiting Bob's final message.
 */
// TODO check OTRv4 spec for instructions on temporarily storing recently received messages while negotiating.
final class StateAwaitingAuthI extends AbstractCommonState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingAuthI.class.getName());

    /**
     * Our ECDH key pair. (Its public key is also known as X.)
     */
    private final ECDHKeyPair ourECDHKeyPair;

    /**
     * Our DH key pair. (Its public key is also known as A.)
     */
    private final DHKeyPair ourDHKeyPair;

    private final ECDHKeyPair ourFirstECDHKeyPair;

    private final DHKeyPair ourFirstDHKeyPair;

    private final Point theirFirstECDHPublicKey;

    private final BigInteger theirFirstDHPublicKey;

    private final Point y;

    private final BigInteger b;

    private final ClientProfilePayload ourProfile;

    private final ClientProfilePayload profileBob;

    private final byte[] ssid;

    private final byte[] k;

    StateAwaitingAuthI(final AuthState authState, final byte[] k, final byte[] ssid, final ECDHKeyPair ourECDHKeyPair,
            final DHKeyPair ourDHKeyPair, final ECDHKeyPair ourFirstECDHKeyPair, final DHKeyPair ourFirstDHKeyPair,
            final Point theirFirstECDHPublicKey, final BigInteger theirFirstDHPublicKey, final Point y,
            final BigInteger b, final ClientProfilePayload ourProfile, final ClientProfilePayload profileBob) {
        super(authState);
        this.ourECDHKeyPair = requireNonNull(ourECDHKeyPair);
        this.ourDHKeyPair = requireNonNull(ourDHKeyPair);
        this.ourFirstECDHKeyPair = requireNonNull(ourFirstECDHKeyPair);
        this.ourFirstDHKeyPair = requireNonNull(ourFirstDHKeyPair);
        this.theirFirstECDHPublicKey = requireNonNull(theirFirstECDHPublicKey);
        this.theirFirstDHPublicKey = requireNonNull(theirFirstDHPublicKey);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.ourProfile = requireNonNull(ourProfile);
        this.profileBob = requireNonNull(profileBob);
        this.k = requireNonNull(k);
        this.ssid = requireNonNull(ssid);
    }

    @Override
    public int getVersion() {
        return FOUR;
    }

    @Nonnull
    @Override
    public SessionStatus getStatus() {
        return PLAINTEXT;
    }

    @Nonnull
    @Override
    public DSAPublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available until encrypted session is fully established.");
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
        if (message instanceof AuthIMessage) {
            try {
                handleAuthIMessage(context, (AuthIMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(WARNING, "Failed to process Auth-I message.", e);
            }
            return;
        }
        // OTR: "Ignore the message."
        LOGGER.log(INFO, "We only expect to receive an Identity message or an Auth-I message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
    }

    /**
     * Handle Identity message.
     * <p>
     * This implementation deviates from the implementation in StateInitial as we reuse previously generated variables.
     * Effectively it is a short-hand, because we, the local user, does not have to start from scratch.
     *
     * @param message the identity message
     * @throws ValidationException In case of failure to validate other party's identity message or client profile.
     */
    // TODO eventually write a test case that demonstrates responses by multiple sessions, such that correct handling of ephemeral keys is mandatory or it will expose the bug.
    @Override
    void handleIdentityMessage(final Context context, final IdentityMessage message) throws OtrException {
        final ClientProfile theirNewClientProfile = message.clientProfile.validate();
        IdentityMessages.validate(message, theirNewClientProfile);
        final SessionID sessionID = context.getSessionID();
        final SecureRandom secureRandom = context.secureRandom();
        // Note: we query the context for a new client profile, because we're responding to a new Identity message.
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final EdDSAKeyPair longTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        final byte[] newK;
        final byte[] newSSID;
        // FIXME we cannot reuse ourDHKeyPair and ourECDHKeyPair as they will have been closed already. (As of yet unresolved issue in Double Ratchet init redesign.)
        try (MixedSharedSecret sharedSecret = new MixedSharedSecret(secureRandom, this.ourDHKeyPair, this.ourECDHKeyPair,
                message.b, message.y)) {
            newK = sharedSecret.getK();
            newSSID = sharedSecret.generateSSID();
        }
        this.ourECDHKeyPair.close();
        this.ourDHKeyPair.close();
        // Generate t value and calculate sigma based on known facts and generated t value.
        final byte[] t = encode(AUTH_R, profilePayload, message.clientProfile, this.ourECDHKeyPair.getPublicKey(),
                message.y, this.ourDHKeyPair.getPublicKey(), message.b, this.ourFirstECDHKeyPair.getPublicKey(),
                this.ourFirstDHKeyPair.getPublicKey(), message.ourFirstECDHPublicKey, message.ourFirstDHPublicKey,
                context.getSenderInstanceTag(), context.getReceiverInstanceTag(), sessionID.getUserID(),
                sessionID.getAccountID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), longTermKeyPair,
                theirNewClientProfile.getForgingKey(), longTermKeyPair.getPublicKey(), message.y, t);
        // Generate response message and transition into next state.
        context.injectMessage(new AuthRMessage(FOUR, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), profilePayload, this.ourECDHKeyPair.getPublicKey(),
                this.ourDHKeyPair.getPublicKey(), sigma, this.ourFirstECDHKeyPair.getPublicKey(),
                this.ourFirstDHKeyPair.getPublicKey()));
        context.transition(this, new StateAwaitingAuthI(getAuthState(), newK, newSSID, this.ourECDHKeyPair,
                this.ourDHKeyPair, this.ourFirstECDHKeyPair, this.ourFirstDHKeyPair, message.ourFirstECDHPublicKey,
                message.ourFirstDHPublicKey, message.y, message.b, ourProfile, message.clientProfile));
    }

    private void handleAuthIMessage(final Context context, final AuthIMessage message) throws ValidationException {
        // Validate message.
        final ClientProfile profileBobValidated = this.profileBob.validate();
        final ClientProfile ourProfileValidated = this.ourProfile.validate();
        validate(message, this.ourProfile, ourProfileValidated, this.profileBob, profileBobValidated,
                this.ourECDHKeyPair.getPublicKey(), this.y, this.ourDHKeyPair.getPublicKey(), this.b,
                this.theirFirstECDHPublicKey, this.theirFirstDHPublicKey, this.ourFirstECDHKeyPair.getPublicKey(),
                this.ourFirstDHKeyPair.getPublicKey(), context.getSessionID().getUserID(),
                context.getSessionID().getAccountID());
        final SecureRandom secureRandom = context.secureRandom();
        // Initialize Double Ratchet.
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(secureRandom, this.ourFirstDHKeyPair,
                this.ourFirstECDHKeyPair, this.theirFirstDHPublicKey, this.theirFirstECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(sharedSecret, kdf(FIRST_ROOT_KEY, ROOT_KEY_LENGTH_BYTES,
                this.k), ALICE);
        secure(context, this.ssid, ratchet, ourProfileValidated.getLongTermPublicKey(),
                ourProfileValidated.getForgingKey(), profileBobValidated.getLongTermPublicKey(),
                profileBobValidated.getForgingKey());
    }

    @Nullable
    @Override
    String handleDataMessage(final Context context, final DataMessage message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv3 data message in state WAITING_AUTH_I. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return null;
    }

    @Nullable
    @Override
    String handleDataMessage(final Context context, final DataMessage4 message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv4 data message in state WAITING_AUTH_I. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return null;
    }

    @Override
    public void end(final Context context) {
        this.ourDHKeyPair.close();
        this.ourECDHKeyPair.close();
        this.ourFirstDHKeyPair.close();
        this.ourFirstECDHKeyPair.close();
        clear(this.k);
        clear(this.ssid);
        context.transition(this, new StatePlaintext(getAuthState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy (i.e. we need to destroy different material for different transitions)
    }
}
