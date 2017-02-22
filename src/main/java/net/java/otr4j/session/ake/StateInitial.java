/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

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
            // OTR: "Ignore the message."
            LOGGER.log(Level.INFO, "We only expect to receive a DH Commit message. Ignoring message with messagetype: {0}", message.getType());
            return null;
        }
        if (message.protocolVersion < 2 || message.protocolVersion > 3) {
            throw new IllegalArgumentException("unsupported protocol version");
        }
        return handleDHCommitMessage(context, (DHCommitMessage) message);
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Nonnull
    private DHKeyMessage handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) {
        // OTR: "Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG."
        // OTR: "Choose a random value y (at least 320 bits), and calculate gy."
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        context.setState(new StateAwaitingRevealSig(message.protocolVersion,
                keypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
        LOGGER.finest("Sending D-H key message.");
        // OTR: "Sends Bob gy"
        return new DHKeyMessage(message.protocolVersion, (DHPublicKey) keypair.getPublic(),
                context.getSenderInstanceTag().getValue(), context.getReceiverInstanceTag().getValue());
    }
}
