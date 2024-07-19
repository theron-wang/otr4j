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
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthIMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.MysteriousT4;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.state.DoubleRatchet;
import net.java.otr4j.session.state.DoubleRatchet.Purpose;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.time.Instant;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH_I_PHI;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FIRST_ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ROOT_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.messages.AuthIMessages.validate;

/**
 * The state AWAITING_AUTH_I.
 * <p>
 * This is a state in which Alice will be while awaiting Bob's final message.
 * <p>
 * Note: the spec. is unclear on whether the Auth-I state should reuse part of its known key-material when processing an
 * Identity-message. This is unclear, but from the protocol it becomes clear that parts of the key-material have already
 * been cleared. So, these cannot be reused. The implementation handles the Identity-message effectively with all-new
 * material as if we process it from the initial state.
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
        context.setDAKEState(new DAKEInitial());
        return new Result(null, new SecurityParameters4(this.ssid, ratchet,
                ourProfileValidated.getLongTermPublicKey(), ourProfileValidated.getForgingKey(), profileBobValidated));
    }
}
