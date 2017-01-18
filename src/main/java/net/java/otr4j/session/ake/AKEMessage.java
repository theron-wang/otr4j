package net.java.otr4j.session.ake;

import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.DHCommitMessage;

// FIXME review try-catch clauses to see if we really accurately handle all possible exception cases.
// TODO see if we can get rid of this class. It doesn't seem to be that useful.
final class AKEMessage {

    private AKEMessage() {
        // No need to instantiate utility class.
    }

    static DHCommitMessage createDHCommitMessage(final int version, final byte[] r,
            final DHPublicKey localPublicKey, final int senderInstance) throws OtrCryptoException {
        final byte[] publicKeyBytes = SerializationUtils.writeMpi(localPublicKey.getY());
        final byte[] publicKeyHash = OtrCryptoEngine.sha256Hash(publicKeyBytes);
        final byte[] publicKeyEncrypted = OtrCryptoEngine.aesEncrypt(r, null, publicKeyBytes);
        return new DHCommitMessage(version, publicKeyHash, publicKeyEncrypted,
                senderInstance, 0);
    }
}
