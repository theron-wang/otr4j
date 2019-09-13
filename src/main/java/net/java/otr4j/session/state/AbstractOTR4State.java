/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import com.google.errorprone.annotations.ForOverride;
import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.logging.Logger;

import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.EncodedMessageParser.parseEncodedMessage;
import static net.java.otr4j.messages.IdentityMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;

abstract class AbstractOTR4State extends AbstractOTR3State {

    private static final Logger LOGGER = Logger.getLogger(AbstractOTR4State.class.getName());

    AbstractOTR4State(final AuthState authState) {
        super(authState);
    }

    @Nullable
    @Override
    public String handleEncodedMessage(final Context context, final EncodedMessage message) throws OtrException {
        if (message.version != FOUR) {
            // FIXME is it going to be an issue if we always delegate on message != OTRv4, even if (*OTRv4*) DAKE in progress/finished?
            return super.handleEncodedMessage(context, message);
        }
        final AbstractEncodedMessage encodedM;
        try {
            encodedM = parseEncodedMessage(message);
        } catch (final ProtocolException e) {
            return null;
        }
        assert !ZERO_TAG.equals(encodedM.receiverTag) || encodedM instanceof IdentityMessage
                : "BUG: receiver instance should be set for anything other than the first AKE message.";
        try {
            final SessionID sessionID = context.getSessionID();
            if (encodedM instanceof DataMessage4) {
                LOGGER.log(FINEST, "{0} received a data message (OTRv4) from {1}, handling in state {2}.",
                        new Object[]{sessionID.getAccountID(), sessionID.getUserID(), this.getClass().getName()});
                return handleDataMessage(context, (DataMessage4) encodedM);
            }
            // Anything that is not a Data message is some type of AKE message.
            handleAKEMessage(context, encodedM);
        } catch (final ProtocolException e) {
            LOGGER.log(FINE, "An illegal message was received. Processing was aborted.", e);
            // TODO consider how we should signal unreadable message for illegal data messages and potentially show error to client. (Where we escape handling logic through ProtocolException.)
        }
        return null;
    }

    /**
     * Method for handling OTRv4 DAKE messages.
     *
     * @param context the session context
     * @param message the AKE message
     * @throws net.java.otr4j.messages.ValidationException In case of failure to validate received message.
     * @throws OtrException                                In case of failure to inject message into the network.
     */
    @ForOverride
    abstract void handleAKEMessage(final Context context, final AbstractEncodedMessage message) throws OtrException;

    /**
     * Common implementation for handling OTRv4 Identity message that is shared among states.
     *
     * @param context the session context
     * @param message the Identity message to be processed
     * @throws net.java.otr4j.messages.ValidationException In case of failure to validate received Identity message.
     */
    void handleIdentityMessage(final Context context, final IdentityMessage message) throws OtrException {
        final ClientProfile theirClientProfile = message.clientProfile.validate();
        validate(message, theirClientProfile);
        final ClientProfilePayload profile = context.getClientProfilePayload();
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair x = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair a = DHKeyPair.generate(secureRandom);
        final ECDHKeyPair ourFirstECDHKeyPair = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair ourFirstDHKeyPair = DHKeyPair.generate(secureRandom);
        final SessionID sessionID = context.getSessionID();
        final EdDSAKeyPair longTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        final byte[] k;
        final byte[] ssid;
        try (MixedSharedSecret sharedSecret = new MixedSharedSecret(secureRandom, a, x, message.b, message.y)) {
            k = sharedSecret.getK();
            ssid = sharedSecret.generateSSID();
        }
        // TODO should we verify that long-term key pair matches with long-term public key from user profile? (This would be an internal sanity check.)
        // Generate t value and calculate sigma based on known facts and generated t value.
        final byte[] t = encode(AUTH_R, profile, message.clientProfile, x.getPublicKey(), message.y, a.getPublicKey(),
                message.b, ourFirstECDHKeyPair.getPublicKey(), ourFirstDHKeyPair.getPublicKey(),
                message.ourFirstECDHPublicKey, message.ourFirstDHPublicKey, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), sessionID.getAccountID(), sessionID.getUserID());
        final Sigma sigma = ringSign(secureRandom, longTermKeyPair, theirClientProfile.getForgingKey(),
                longTermKeyPair.getPublicKey(), message.y, t);
        // Generate response message and transition into next state.
        context.injectMessage(new AuthRMessage(FOUR, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), profile, x.getPublicKey(), a.getPublicKey(), sigma,
                ourFirstECDHKeyPair.getPublicKey(), ourFirstDHKeyPair.getPublicKey()));
        context.transition(this, new StateAwaitingAuthI(getAuthState(), k, ssid, x, a, ourFirstECDHKeyPair,
                ourFirstDHKeyPair, message.ourFirstECDHPublicKey, message.ourFirstDHPublicKey, message.y, message.b,
                profile, message.clientProfile));
    }

    @Override
    public void initiateAKE(final Context context, final int version, final InstanceTag receiverInstanceTag)
            throws OtrException {
        if (version != FOUR) {
            super.initiateAKE(context, version, receiverInstanceTag);
            return;
        }
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair ourECDHkeyPair = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair ourDHkeyPair = DHKeyPair.generate(secureRandom);
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final ECDHKeyPair ourFirstECDHKeyPair = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair ourFirstDHKeyPair = DHKeyPair.generate(secureRandom);
        final IdentityMessage message = new IdentityMessage(FOUR, context.getSenderInstanceTag(),
                receiverInstanceTag, profilePayload, ourECDHkeyPair.getPublicKey(), ourDHkeyPair.getPublicKey(),
                ourFirstECDHKeyPair.getPublicKey(), ourFirstDHKeyPair.getPublicKey());
        context.injectMessage(message);
        context.transition(this, new StateAwaitingAuthR(getAuthState(), ourECDHkeyPair, ourDHkeyPair,
                ourFirstECDHKeyPair, ourFirstDHKeyPair, profilePayload, message));
    }

    /**
     * Secure existing session, i.e. transition to `ENCRYPTED_MESSAGES`. This ensures that, apart from transitioning to
     * the encrypted messages state, that we also set the default outgoing session to this instance, if the current
     * outgoing session is not secured yet.
     *
     * @param context                the session context
     * @param ssid                   the session's SSID
     * @param ratchet                the initialized double ratchet
     * @param ourLongTermPublicKey   our long-term public key as used in the DAKE
     * @param theirLongTermPublicKey their long-term public key as used in the DAKE
     */
    final void secure(final Context context, final byte[] ssid, final DoubleRatchet ratchet,
            final Point ourLongTermPublicKey, final Point ourForgingKey, final Point theirLongTermPublicKey,
            final Point theirForgingKey) {
        context.transition(this, new StateEncrypted4(context, ssid, ourLongTermPublicKey, ourForgingKey,
                theirLongTermPublicKey, theirForgingKey, ratchet, getAuthState()));
        if (context.getSessionStatus() != ENCRYPTED) {
            throw new IllegalStateException("Session failed to transition to ENCRYPTED (OTRv4).");
        }
        LOGGER.info("Session secured. Message state transitioned to ENCRYPTED. (OTRv4)");
    }

    /**
     * Handle the received data message in OTRv4 format.
     *
     * @param message The received data message.
     * @return Returns the decrypted message text.
     * @throws ProtocolException In case of I/O reading failures.
     * @throws OtrException      In case of failures regarding the OTR protocol (implementation).
     */
    @ForOverride
    @Nullable
    abstract String handleDataMessage(Context context, DataMessage4 message) throws ProtocolException, OtrException;
}
