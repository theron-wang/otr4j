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

final class StateAwaitingDHKey implements State {

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
        // FIXME validate non-null, valid value
        this.keypair = Objects.requireNonNull(keypair);
        // FIXME validate non-null, random value (non-zero), expected length
        this.r = Objects.requireNonNull(r);
    }

    @Override
    public DHCommitMessage initiate(@Nonnull final Context context, final int version) {
        // TODO duplicate code for creating DH Commit message.
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

    @Override
    public AbstractEncodedMessage handle(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException {
        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (version != this.version) {
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
    private AbstractEncodedMessage handleDHCommitMessage(@Nonnull final Context context, @Nonnull final DHCommitMessage message) throws OtrCryptoException {
        final byte[] publicKeyBytes = SerializationUtils.writeMpi(((DHPublicKey) keypair.getPublic()).getY());
        final byte[] publicKeyHash = OtrCryptoEngine.sha256Hash(publicKeyBytes);
        final BigInteger localKeyHashBigInt = new BigInteger(1, publicKeyHash);
        final BigInteger remoteKeyHashBigInt = new BigInteger(1, message.dhPublicKeyHash);
        if (localKeyHashBigInt.compareTo(remoteKeyHashBigInt) > 0) {
            LOGGER.finest("Ignored the incoming D-H Commit message, but resent our D-H Commit message.");
            // TODO spec seems to suggest that we need to resend the exact same DH commit message. So we do not generate a new random AES key, but instead reause the existing one.
            final byte[] publicKeyEncrypted = OtrCryptoEngine.aesEncrypt(this.r, null, publicKeyBytes);
            return new DHCommitMessage(this.version, publicKeyHash, publicKeyEncrypted, context.senderInstance(), 0);
        } else {
            LOGGER.finest("Forgetting old gx value that we sent (encrypted) earlier, and pretended we're in AUTHSTATE_NONE -> Sending DH key.");
            // TODO consider generating a new DH keypair, as we do not rely on activity up to now anymore. (as per spec we imagine we're back in NONE auth state.
            context.setState(new StateAwaitingRevealSig(message.protocolVersion, this.keypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
            return new DHKeyMessage(message.protocolVersion, (DHPublicKey) this.keypair.getPublic(), context.senderInstance(), context.receiverInstance());
        }
    }

    @Nonnull
    private AbstractEncodedMessage handleDHKeyMessage(@Nonnull final Context context, @Nonnull final DHKeyMessage message) throws OtrCryptoException {
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
