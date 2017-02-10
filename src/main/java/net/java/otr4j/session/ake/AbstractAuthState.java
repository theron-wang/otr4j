package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.SerializationUtils;
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
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        final byte[] r = OtrCryptoEngine.random(context.secureRandom(),
                new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH]);
        final DHPublicKey localDHPublicKey = (DHPublicKey) keypair.getPublic();
        try {
            OtrCryptoEngine.verify(localDHPublicKey);
        } catch (final OtrCryptoException ex) {
            // Caught and handled here as all components are constructed here
            // and failure should thus be considered a programming error.
            throw new IllegalStateException("Failed to generate valid local DH keypair.", ex);
        }
        final byte[] publicKeyBytes = SerializationUtils.writeMpi(localDHPublicKey.getY());
        final byte[] publicKeyHash = OtrCryptoEngine.sha256Hash(publicKeyBytes);
        final byte[] publicKeyEncrypted;
        try {
            publicKeyEncrypted = OtrCryptoEngine.aesEncrypt(r, null, publicKeyBytes);
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to encrypt public key bytes.", ex);
        }
        final DHCommitMessage dhcommit = new DHCommitMessage(version,
                publicKeyHash, publicKeyEncrypted, context.senderInstance(), 0);
        LOGGER.finest("Sending DH commit message.");
        context.setState(new StateAwaitingDHKey(version, keypair, r));
        return dhcommit;
    }
}
