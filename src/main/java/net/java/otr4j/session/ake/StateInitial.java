package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;

/**
 * Initial AKE state, a.k.a. NONE. (Singleton)
 *
 * @author Danny van Heumen
 */
public final class StateInitial extends AbstractAuthState {

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
