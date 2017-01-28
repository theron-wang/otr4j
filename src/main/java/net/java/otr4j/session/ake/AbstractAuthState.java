package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.DHCommitMessage;

/**
 * Abstract AuthState implementation that provides authentication initiation
 * as this is supported in any state and is always processed in the same manner.
 *
 * @author Danny van Heumen
 */
abstract class AbstractAuthState implements AuthState {

    private static final Logger LOGGER = Logger.getLogger(AbstractAuthState.class.getName());

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

}
