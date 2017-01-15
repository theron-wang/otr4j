package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;

public final class StateInitial implements State {

    private static final Logger LOGGER = Logger.getLogger(StateInitial.class.getCanonicalName());

    @Override
    public DHCommitMessage initiate(@Nonnull final Context context, final int version) {
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unknown or unsupported protocol version");
        }
        final KeyPair keypair = generateKeyPair(context.secureRandom());
        final byte[] r = OtrCryptoEngine.random(context.secureRandom(),
                new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH]);
        final DHCommitMessage dhcommit = AKEMessage.createDHCommitMessage(
                version, r, (DHPublicKey) keypair.getPublic(),
                context.senderInstance());
        context.setState(new StateAwaitingDHKey(version, keypair, r));
        return dhcommit;
    }

    @Override
    public AbstractEncodedMessage handle(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) {
        if (!(message instanceof DHCommitMessage)) {
            LOGGER.log(Level.INFO, "We only expect to receive a DH Commit message. Ignoring message with messagetype: {0}", message.messageType);
            return null;
        }
        if (message.protocolVersion < 2 || message.protocolVersion > 3) {
            // TODO consider verifying this at an earlier part of the handling process. On the other hand, we cannot fully verify as we also want to catch message in a valid conversation but which switches versions in between.
            throw new IllegalArgumentException("unsupported protocol version");
        }
        final DHCommitMessage commitMessage = (DHCommitMessage) message;
        final KeyPair keypair = generateKeyPair(context.secureRandom());
        // FIXME need to set version in session?
        LOGGER.finest("Sending DH key message.");
        context.setState(new StateAwaitingRevealSig(commitMessage.protocolVersion, keypair, commitMessage.dhPublicKeyHash, commitMessage.dhPublicKeyEncrypted));
        return new DHKeyMessage(commitMessage.protocolVersion, (DHPublicKey) keypair.getPublic(), context.senderInstance(), context.receiverInstance());
    }

    // TODO this method is not necessary here ... it should be a utility method.
    private KeyPair generateKeyPair(@Nonnull final SecureRandom secureRandom) {
        try {
            final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(secureRandom);
            LOGGER.finest("Generated local D-H key pair.");
            return keypair;
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to generate DH keypair.", ex);
        }
    }
}
