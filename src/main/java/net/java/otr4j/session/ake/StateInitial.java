package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;

/**
 * Initial AKE state, a.k.a. NONE. (Singleton)
 *
 * @author Danny van Heumen
 */
public final class StateInitial implements AuthState {

    private static final Logger LOGGER = Logger.getLogger(StateInitial.class.getName());

    /**
     * Singleton instance.
     */
    private static final StateInitial INSTANCE = new StateInitial();

    private StateInitial() {
        // Singleton, we only need to instantiate a single instance that can
        // then be reused in all sessions. Given that this is the initial state
        // we have no state on an AKE negotiation yet.
    }

    /**
     * Acquire the Singleton instance for StateInitial.
     *
     * @return Returns the singleton instance.
     */
    @Nonnull
    public static StateInitial instance() {
        return INSTANCE;
    }

    @Nonnull
    @Override
    public DHCommitMessage initiate(@Nonnull final AuthContext context, final int version) {
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unknown or unsupported protocol version");
        }
        final KeyPair newKeypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        final byte[] newR = OtrCryptoEngine.random(context.secureRandom(),
                new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH]);
        final DHCommitMessage dhcommit;
        try {
            dhcommit = AKEMessage.createDHCommitMessage(
                    version, newR, (DHPublicKey) newKeypair.getPublic(),
                    context.senderInstance());
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to create DH Commit message.", ex);
        }
        LOGGER.finest("Sending DH commit message.");
        context.setState(new StateAwaitingDHKey(version, newKeypair, newR));
        return dhcommit;
    }

    @Nullable
    @Override
    public DHKeyMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) {
        if (!(message instanceof DHCommitMessage)) {
            LOGGER.log(Level.INFO, "We only expect to receive a DH Commit message. Ignoring message with messagetype: {0}", message.messageType);
            return null;
        }
        if (message.protocolVersion < 2 || message.protocolVersion > 3) {
            // TODO consider verifying this at an earlier part of the handling
            // process. On the other hand, we cannot fully verify as we also
            // want to catch message in a valid conversation but which switches
            // versions in between.
            throw new IllegalArgumentException("unsupported protocol version");
        }
        return handleDHCommitMessage(context, (DHCommitMessage) message);
    }

    @Override
    public int getVersion() {
        // FIXME should we return 0 here ... does that really help?
        return 0;
    }

    @Nonnull
    private DHKeyMessage handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        context.setState(new StateAwaitingRevealSig(message.protocolVersion,
                keypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
        LOGGER.finest("Sending DH key message.");
        return new DHKeyMessage(message.protocolVersion, (DHPublicKey) keypair.getPublic(),
                context.senderInstance(), context.receiverInstance());
    }
}
