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
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.OtrOutputStream;
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
import static net.java.otr4j.messages.AuthRMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_I;

/**
 * OTRv4 AKE state AWAITING_AUTH_R.
 */
final class DAKEAwaitingAuthR extends AbstractState implements DAKEState {

    private static final Logger LOGGER = Logger.getLogger(DAKEAwaitingAuthR.class.getName());

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

    DAKEAwaitingAuthR(final ECDHKeyPair y, final DHKeyPair b, final ECDHKeyPair firstECDHKeyPair,
            final DHKeyPair firstDHKeyPair, final ClientProfilePayload profilePayload,
            final IdentityMessage previousMessage) {
        super();
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.firstECDHKeyPair = requireNonNull(firstECDHKeyPair);
        this.firstDHKeyPair = requireNonNull(firstDHKeyPair);
        this.profilePayload = requireNonNull(profilePayload);
        this.previousMessage = requireNonNull(previousMessage);
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
        if (message instanceof AuthRMessage) {
            try {
                return handleAuthRMessage(context, (AuthRMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(WARNING, "Failed to process Auth-R message.", e);
                return new Result();
            }
        }
        // OTR: "Ignore the message."
        LOGGER.log(INFO, "We only expect to receive an Identity message or an Auth-R message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
        return new Result();
    }

    @Nonnull
    @Override
    Result handleIdentityMessage(final DAKEContext context, final IdentityMessage message) throws ValidationException {
        final ClientProfile theirProfile = message.clientProfile.validate(Instant.now());
        IdentityMessages.validate(message, theirProfile);
        final BigInteger ourHashedB = new BigInteger(1, OtrCryptoEngine4.shake256(32,
                new OtrOutputStream().writeBigInt(this.previousMessage.b).toByteArray()));
        final BigInteger theirHashedB = new BigInteger(1, OtrCryptoEngine4.shake256(32,
                new OtrOutputStream().writeBigInt(message.b).toByteArray()));
        if (ourHashedB.compareTo(theirHashedB) > 0) {
            // No state change necessary, we assume that, by resending, other party will still follow existing protocol
            // execution.
            return new Result(this.previousMessage, null);
        }
        // Clear old key material, then start a new DAKE from scratch with different keys.
        this.b.close();
        this.y.close();
        // Pretend we are still in initial state and handle Identity message accordingly.
        return super.handleIdentityMessage(context, message);
    }

    @Nonnull
    private Result handleAuthRMessage(final DAKEContext context, final AuthRMessage message) throws ValidationException {
        final SessionID sessionID = context.getSessionID();
        final EdDSAKeyPair ourLongTermKeyPair = context.getLongTermKeyPair();
        // Validate received Auth-R message.
        final ClientProfile ourClientProfile = this.profilePayload.validate(Instant.now());
        final ClientProfile theirClientProfile = message.clientProfile.validate(Instant.now());
        final byte[] phiR = MysteriousT4.generatePhi(AUTH_R_PHI, message.senderTag, message.receiverTag,
                message.firstECDHPublicKey, message.firstDHPublicKey, this.firstECDHKeyPair.publicKey(),
                this.firstDHKeyPair.publicKey(), sessionID.getUserID(), sessionID.getAccountID());
        validate(message, this.profilePayload, ourClientProfile, theirClientProfile, this.y.publicKey(),
                this.b.publicKey(), phiR);
        final SecureRandom secureRandom = context.secureRandom();
        // Prepare Auth-I message to be sent.
        final InstanceTag senderTag = context.getSenderInstanceTag();
        final InstanceTag receiverTag = context.getReceiverInstanceTag();
        final byte[] phiI = MysteriousT4.generatePhi(AUTH_I_PHI, senderTag, receiverTag,
                this.firstECDHKeyPair.publicKey(), this.firstDHKeyPair.publicKey(),
                message.firstECDHPublicKey, message.firstDHPublicKey, sessionID.getAccountID(), sessionID.getUserID());
        final byte[] t = MysteriousT4.encode(AUTH_I, this.profilePayload, message.clientProfile, this.y.publicKey(),
                message.x, this.b.publicKey(), message.a, phiI);
        final OtrCryptoEngine4.Sigma sigma = ringSign(secureRandom, ourLongTermKeyPair,
                ourLongTermKeyPair.getPublicKey(), theirClientProfile.getForgingKey(), message.x, t);
        final AuthIMessage response = new AuthIMessage(senderTag, receiverTag, sigma);
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
        final DoubleRatchet ratchet = DoubleRatchet.initialize(Purpose.RECEIVING, firstRatchetSecret,
                kdf(ROOT_KEY_LENGTH_BYTES, FIRST_ROOT_KEY, k));
        context.setDAKEState(DAKEInitial.instance());
        return new Result(response, new SecurityParameters4(ssid, ratchet, ourClientProfile.getLongTermPublicKey(),
                ourClientProfile.getForgingKey(), theirClientProfile));
    }
}
