/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.dake;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthIMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.IdentityMessages;
import net.java.otr4j.messages.MysteriousT4;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.state.DoubleRatchet;
import net.java.otr4j.session.state.DoubleRatchet.Purpose;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH_I_PHI;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH_R_PHI;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FIRST_ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ROOT_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthIMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;

/**
 * The state AWAITING_AUTH_I.
 * <p>
 * This is a state in which Alice will be while awaiting Bob's final message.
 */
final class DAKEAwaitingAuthI extends AbstractState implements DAKEState {

    private static final Logger LOGGER = Logger.getLogger(DAKEAwaitingAuthI.class.getName());

    /**
     * Our ECDH key pair. (Its public key is also known as X.)
     */
    private final ECDHKeyPair x;

    /**
     * Our DH key pair. (Its public key is also known as A.)
     */
    private final DHKeyPair a;

    private final ECDHKeyPair firstECDHKeyPair;

    private final DHKeyPair firstDHKeyPair;

    private final Point theirFirstECDHPublicKey;

    private final BigInteger theirFirstDHPublicKey;

    private final Point y;

    private final BigInteger b;

    private final ClientProfilePayload ourProfile;

    private final ClientProfilePayload profileBob;

    private final byte[] ssid;

    private final byte[] k;

    // TODO we don't need the full keypairs anymore. Only pass on the public keys?
    DAKEAwaitingAuthI(final byte[] k, final byte[] ssid, final ECDHKeyPair x,
            final DHKeyPair a, final ECDHKeyPair ourFirstECDHKeyPair, final DHKeyPair ourFirstDHKeyPair, final Point y,
            final BigInteger b, final Point theirFirstECDHPublicKey, final BigInteger theirFirstDHPublicKey,
            final ClientProfilePayload ourProfile, final ClientProfilePayload profileBob) {
        super();
        // TODO add requireNotEquals checks for y, b, ourFirst, etc.
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
        this.firstECDHKeyPair = requireNonNull(ourFirstECDHKeyPair);
        this.firstDHKeyPair = requireNonNull(ourFirstDHKeyPair);
        this.theirFirstECDHPublicKey = requireNonNull(theirFirstECDHPublicKey);
        this.theirFirstDHPublicKey = requireNonNull(theirFirstDHPublicKey);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.ourProfile = requireNonNull(ourProfile);
        this.profileBob = requireNonNull(profileBob);
        this.k = requireNonNull(k);
        this.ssid = requireNonNull(ssid);
    }

    @Nonnull
    @Override
    public Result handle(final DAKEContext context, final AbstractEncodedMessage message) {
        if (message instanceof IdentityMessage) {
            try {
                return handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(INFO, "Failed to process Identity message.", e);
                return new Result();
            }
        }
        if (message instanceof AuthIMessage) {
            try {
                return handleAuthIMessage(context, (AuthIMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(WARNING, "Failed to process Auth-I message.", e);
                return new Result();
            }
        }
        // OTR: "Ignore the message."
        LOGGER.log(INFO, "We only expect to receive an Identity message or an Auth-I message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
        return new Result();
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
    // FIXME this is (seems to be) the exact implementation as the first `handleIdentityMessage`. We can probably drop this and use the one in AbstractState, and the only thing we lose is the additional commentary that makes explicit that we start with a blank slate.
    @Nonnull
    @Override
    Result handleIdentityMessage(final DAKEContext context, final IdentityMessage message) throws ValidationException {
        final ClientProfile theirNewClientProfile = message.clientProfile.validate(Instant.now());
        IdentityMessages.validate(message, theirNewClientProfile);
        final SessionID sessionID = context.getSessionID();
        final SecureRandom secureRandom = context.secureRandom();
        // Note: we query the context for a new client profile, because we're responding to a new Identity message.
        // The spec is not explicit in that we need to generate new keypairs. We do this, because the alternative would
        // be logically incorrect as the secret key material was already cleared. This effectively starts a new key
        // exchange as we do not reuse any key material from the on-going key exchange.
        final byte[] newK;
        final byte[] newSSID;
        // REMARK not yet corrected in OTRv4 specification: generating new key material, not-clearing public key because needed in validation with ring-signatures.
        // TODO this looks like it is effectively same as clearing the existing state and calling super.handleIdentityMessage(). (Just like in StateAwaitingAuthR.)
        final ECDHKeyPair newX = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair newA = DHKeyPair.generate(secureRandom);
        final ECDHKeyPair newFirstECDHKeyPair = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair newFirstDHKeyPair = DHKeyPair.generate(secureRandom);
        try (MixedSharedSecret sharedSecret = new MixedSharedSecret(secureRandom, newX, newA, message.y, message.b)) {
            newK = sharedSecret.getK();
            newSSID = sharedSecret.generateSSID();
        }
        newA.close();
        newX.close();
        // Generate t value and calculate sigma based on known facts and generated t value.
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final EdDSAKeyPair longTermKeyPair = context.getLongTermKeyPair();
        final byte[] phi = MysteriousT4.generatePhi(AUTH_R_PHI, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), newFirstECDHKeyPair.publicKey(), newFirstDHKeyPair.publicKey(),
                message.firstECDHPublicKey, message.firstDHPublicKey, sessionID.getAccountID(), sessionID.getUserID());
        final byte[] t = MysteriousT4.encode(AUTH_R, message.clientProfile, profilePayload,
                message.y, newX.publicKey(), message.b, newA.publicKey(), phi);
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), longTermKeyPair,
                theirNewClientProfile.getForgingKey(), longTermKeyPair.getPublicKey(), message.y, t);
        // Generate response message and transition into next state.
        final AuthRMessage response = new AuthRMessage(context.getSenderInstanceTag(), context.getReceiverInstanceTag(),
                profilePayload, newX.publicKey(), newA.publicKey(), sigma, newFirstECDHKeyPair.publicKey(),
                newFirstDHKeyPair.publicKey());
        context.setDAKEState(new DAKEAwaitingAuthI(newK, newSSID, newX, newA, newFirstECDHKeyPair,
                newFirstDHKeyPair, message.y, message.b, message.firstECDHPublicKey, message.firstDHPublicKey,
                this.ourProfile, message.clientProfile));
        return new Result(response, null);
    }

    @Nonnull
    private Result handleAuthIMessage(final DAKEContext context, final AuthIMessage message) throws ValidationException {
        // Validate message.
        final ClientProfile profileBobValidated = this.profileBob.validate(Instant.now());
        final ClientProfile ourProfileValidated = this.ourProfile.validate(Instant.now());
        final byte[] phi = MysteriousT4.generatePhi(AUTH_I_PHI, message.senderTag, message.receiverTag,
                this.theirFirstECDHPublicKey, this.theirFirstDHPublicKey, this.firstECDHKeyPair.publicKey(),
                this.firstDHKeyPair.publicKey(), context.getSessionID().getUserID(),
                context.getSessionID().getAccountID());
        validate(message, this.ourProfile, ourProfileValidated, this.profileBob, profileBobValidated,
                this.x.publicKey(), this.y, this.a.publicKey(), this.b, phi);
        // Initialize Double Ratchet.
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(context.secureRandom(),
                this.firstECDHKeyPair, this.firstDHKeyPair, this.theirFirstECDHPublicKey, this.theirFirstDHPublicKey);
        final DoubleRatchet ratchet = DoubleRatchet.initialize(Purpose.SENDING, sharedSecret,
                kdf(ROOT_KEY_LENGTH_BYTES, FIRST_ROOT_KEY, this.k));
        context.setDAKEState(DAKEInitial.instance());
        return new Result(null, new SecurityParameters4(this.ssid, ratchet,
                ourProfileValidated.getLongTermPublicKey(), ourProfileValidated.getForgingKey(), profileBobValidated));
    }
}
