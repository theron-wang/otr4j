package net.java.otr4j.session.ake;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureM;
import net.java.otr4j.io.messages.SignatureX;

/**
 * AKE state Awaiting D-H Key message, a.k.a. AUTHSTATE_AWAITING_DHKEY.
 *
 * @author Danny van Heumen
 */
final class StateAwaitingDHKey extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingDHKey.class.getName());

    private static final int LOCAL_DH_PRIVATE_KEY_ID = 1;

    private final int version;
    private final KeyPair keypair;
    private final byte[] r;

    StateAwaitingDHKey(final int version, @Nonnull final KeyPair keypair, @Nonnull final byte[] r) {
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unsupported version specified");
        }
        this.version = version;
        this.keypair = Objects.requireNonNull(keypair);
        if (r.length != OtrCryptoEngine.AES_KEY_BYTE_LENGTH) {
            throw new IllegalArgumentException("Invalid random value: expected 128-bit random value.");
        }
        this.r = r;
    }

    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException {
        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (message.protocolVersion != this.version) {
            throw new IllegalArgumentException("unexpected version");
        }
        if (!(message instanceof DHKeyMessage)) {
            LOGGER.log(Level.FINEST, "Only expected message is DHKeyMessage. Ignoring message with type: {0}", message.messageType);
            return null;
        }
        return handleDHKeyMessage(context, (DHKeyMessage) message);
    }

    @Override
    public int getVersion() {
        return this.version;
    }

    @Nonnull
    private AbstractEncodedMessage handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) throws OtrCryptoException {
        final byte[] publicKeyBytes = SerializationUtils.writeMpi(((DHPublicKey) keypair.getPublic()).getY());
        final byte[] publicKeyHash = OtrCryptoEngine.sha256Hash(publicKeyBytes);
        final BigInteger localKeyHashBigInt = new BigInteger(1, publicKeyHash);
        final BigInteger remoteKeyHashBigInt = new BigInteger(1, message.dhPublicKeyHash);
        if (localKeyHashBigInt.compareTo(remoteKeyHashBigInt) > 0) {
            LOGGER.finest("Ignored the incoming D-H Commit message, but resent our D-H Commit message.");
            final byte[] publicKeyEncrypted = OtrCryptoEngine.aesEncrypt(this.r, null, publicKeyBytes);
            return new DHCommitMessage(this.version, publicKeyHash, publicKeyEncrypted, context.senderInstance(), 0);
        } else {
            LOGGER.finest("Forgetting old gx value that we sent (encrypted) earlier, and pretended we're in AUTHSTATE_NONE -> Sending DH key.");
            final KeyPair newKeypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
            context.setState(new StateAwaitingRevealSig(message.protocolVersion, newKeypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
            return new DHKeyMessage(message.protocolVersion, (DHPublicKey) newKeypair.getPublic(), context.senderInstance(), context.receiverInstance());
        }
    }

    @Nonnull
    private RevealSignatureMessage handleDHKeyMessage(@Nonnull final AuthContext context, @Nonnull final DHKeyMessage message) throws OtrCryptoException {
        OtrCryptoEngine.verify(message.dhPublicKey);
        final KeyPair longTermKeyPair = context.longTermKeyPair();
        final SharedSecret s = OtrCryptoEngine.generateSecret(this.keypair.getPrivate(), message.dhPublicKey);
        final SignatureM sigM = new SignatureM(
                (DHPublicKey) this.keypair.getPublic(), message.dhPublicKey,
                longTermKeyPair.getPublic(), LOCAL_DH_PRIVATE_KEY_ID);
        final byte[] mhash = OtrCryptoEngine.sha256Hmac(SerializationUtils
                    .toByteArray(sigM), s.m1());
        final byte[] signature = OtrCryptoEngine.sign(mhash, longTermKeyPair.getPrivate());
        final SignatureX mysteriousX = new SignatureX(longTermKeyPair.getPublic(),
                LOCAL_DH_PRIVATE_KEY_ID, signature);
        final byte[] xEncrypted = OtrCryptoEngine.aesEncrypt(s.c(), null,
                    SerializationUtils.toByteArray(mysteriousX));
        final byte[] tmpEncrypted = SerializationUtils.writeData(xEncrypted);
        final byte[] xEncryptedHash = OtrCryptoEngine.sha256Hmac160(tmpEncrypted, s.m2());
        final RevealSignatureMessage revealSigMessage = new RevealSignatureMessage(
                this.version, xEncrypted, xEncryptedHash, this.r,
                context.senderInstance(), context.receiverInstance());
        context.setState(new StateAwaitingSig(this.version, this.keypair,
                message.dhPublicKey, s, revealSigMessage));
        return revealSigMessage;
    }
}
