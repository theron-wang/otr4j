package net.java.otr4j.session.ake;

import java.io.IOException;
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
import net.java.otr4j.io.messages.SignatureMessage;
import net.java.otr4j.io.messages.SignatureX;

final class StateAwaitingRevealSig implements State {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingRevealSig.class.getName());

    private static final int LOCAL_DH_PRIVATE_KEY_ID = 1;

    private final int version;
    private final KeyPair keypair;
    private final byte[] remotePublicKeyHash;
    private final byte[] remotePublicKeyEncrypted;

    StateAwaitingRevealSig(final int version, @Nonnull final KeyPair keypair,
            @Nonnull final byte[] remotePublicKeyHash,
            @Nonnull final byte[] remotePublicKeyEncrypted) {
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unsupported version specified");
        }
        this.version = version;
        this.keypair = Objects.requireNonNull(keypair);
        if (remotePublicKeyHash.length != 32) {
            throw new IllegalArgumentException("Expected public key hash with length of 32 bytes.");
        }
        this.remotePublicKeyHash = remotePublicKeyHash;
        if (remotePublicKeyEncrypted.length <= 0) {
            throw new IllegalArgumentException("Expected public key ciphertext having actual contents.");
        }
        this.remotePublicKeyEncrypted = Objects.requireNonNull(remotePublicKeyEncrypted);
    }

    @Override
    public DHCommitMessage initiate(Context context, int version) {
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

    // FIXME current implementation has risk of mixing up variables from Reveal Signature message validation and Signature message creation.
    @Override
    public AbstractEncodedMessage handle(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message)
            throws OtrCryptoException, Context.InteractionFailedException, IOException {
        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        } else if (message instanceof DHKeyMessage) {
            LOGGER.log(Level.INFO, "Ignoring DHKey message.");
            return null;
        }
        if (version != this.version) {
            // FIXME need to move version-check up?
            throw new IllegalArgumentException("unexpected version");
        }
        if (!(message instanceof RevealSignatureMessage)) {
            // TODO is this correct, didn't check all possible cases, so far just implemented handling Reveal Signature Message.
            LOGGER.log(Level.INFO, "Ignoring message.");
            return null;
        }
        return handleRevealSignatureMessage(context, (RevealSignatureMessage) message);
    }

    @Override
    public int getVersion() {
        return this.version;
    }

    @Nonnull
    private DHKeyMessage handleDHCommitMessage(@Nonnull final Context context, @Nonnull final DHCommitMessage message) {
        context.setState(new StateAwaitingRevealSig(message.protocolVersion, this.keypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
        return new DHKeyMessage(message.protocolVersion, (DHPublicKey) this.keypair.getPublic(), context.senderInstance(), context.receiverInstance());
    }

    @Nonnull
    private SignatureMessage handleRevealSignatureMessage(@Nonnull final Context context, @Nonnull final RevealSignatureMessage message)
            throws OtrCryptoException, Context.InteractionFailedException, IOException {
        // Start validation of Reveal Signature message.
        final byte[] remotePublicKeyBytes = OtrCryptoEngine.aesDecrypt(message.revealedKey, null, this.remotePublicKeyEncrypted);
        final byte[] expectedRemotePublicKeyHash = OtrCryptoEngine.sha256Hash(remotePublicKeyBytes);
        OtrCryptoEngine.checkEquals(this.remotePublicKeyHash, expectedRemotePublicKeyHash, "Remote's public key hash failed validation.");
        final BigInteger remotePublicKeyMPI = SerializationUtils.readMpi(remotePublicKeyBytes);
        final DHPublicKey remoteDHPublicKey = OtrCryptoEngine.verify(
                OtrCryptoEngine.getDHPublicKey(remotePublicKeyMPI));
        final SharedSecret s = OtrCryptoEngine.generateSecret(this.keypair.getPrivate(), remoteDHPublicKey);
        final byte[] remoteXEncryptedBytes = SerializationUtils.writeData(message.xEncrypted);
        final byte[] expectedXEncryptedMAC = OtrCryptoEngine.sha256Hmac160(remoteXEncryptedBytes, s.m2());
        OtrCryptoEngine.checkEquals(message.xEncryptedMAC, expectedXEncryptedMAC, "xEncryptedMAC failed validation.");
        final byte[] remoteMysteriousXBytes = OtrCryptoEngine.aesDecrypt(s.c(), null, message.xEncrypted);
        final SignatureX remoteMysteriousX = SerializationUtils.toMysteriousX(remoteMysteriousXBytes);
        final SignatureM expectedM = new SignatureM(remoteDHPublicKey,
                (DHPublicKey) this.keypair.getPublic(),
                remoteMysteriousX.longTermPublicKey, remoteMysteriousX.dhKeyID);
        final byte[] expectedMBytes = SerializationUtils.toByteArray(expectedM);
        final byte[] expectedSignature = OtrCryptoEngine.sha256Hmac(expectedMBytes, s.m1());
        OtrCryptoEngine.verify(expectedSignature, remoteMysteriousX.longTermPublicKey,
                remoteMysteriousX.signature);
        LOGGER.finest("Signature verification succeeded.");
        // Start construction of Signature message.
        final KeyPair localLongTermKeyPair = context.longTermKeyPair();
        final SignatureM signatureM = new SignatureM(
                (DHPublicKey) this.keypair.getPublic(), remoteDHPublicKey,
                localLongTermKeyPair.getPublic(), LOCAL_DH_PRIVATE_KEY_ID);
        final byte[] signatureMBytes = SerializationUtils.toByteArray(signatureM);
        final byte[] mhash = OtrCryptoEngine.sha256Hmac(signatureMBytes, s.m1p());
        final byte[] signature = OtrCryptoEngine.sign(mhash, localLongTermKeyPair.getPrivate());
        final SignatureX mysteriousX = new SignatureX(localLongTermKeyPair.getPublic(),
                LOCAL_DH_PRIVATE_KEY_ID, signature);
        final byte[] xEncrypted = OtrCryptoEngine.aesEncrypt(s.cp(), null,
                    SerializationUtils.toByteArray(mysteriousX));
        final byte[] xEncryptedBytes = SerializationUtils.writeData(xEncrypted);
        final byte[] xEncryptedHash = OtrCryptoEngine.sha256Hmac160(xEncryptedBytes, s.m2p());
        final SignatureMessage signatureMessage = new SignatureMessage(
                this.version, xEncrypted, xEncryptedHash, context.senderInstance(), context.receiverInstance());
        // Transition to ENCRYPTED message state.
        final SecurityParameters params = new SecurityParameters(this.version,
                this.keypair, remoteMysteriousX.longTermPublicKey,
                remoteDHPublicKey, s);
        context.secure(params);
        context.setState(StateInitial.instance());
        return signatureMessage;
    }
}
