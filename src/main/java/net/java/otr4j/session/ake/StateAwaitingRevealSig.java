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

// FIXME currently IOExceptions get wrapped with IllegalStateException --> FIX!
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
        // FIXME validate non-null, keypair
        this.keypair = Objects.requireNonNull(keypair);
        // FIXME validate non-null, non-zero?, correct length
        this.remotePublicKeyHash = Objects.requireNonNull(remotePublicKeyHash);
        // FIXME validate non-null, non-zero?, correct length?
        this.remotePublicKeyEncrypted = Objects.requireNonNull(remotePublicKeyEncrypted);
    }

    @Override
    public DHCommitMessage initiate(Context context, int version) {
        // TODO duplicate code for creating DH Commit message.
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unknown or unsupported protocol version");
        }
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        final byte[] r = OtrCryptoEngine.random(context.secureRandom(),
                new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH]);
        final DHCommitMessage dhcommit = AKEMessage.createDHCommitMessage(
                version, r, (DHPublicKey) keypair.getPublic(),
                context.senderInstance());
        LOGGER.finest("Sending DH commit message.");
        context.setState(new StateAwaitingDHKey(version, keypair, r));
        return dhcommit;
    }

    // FIXME current implementation has risk of mixing up variables from Reveal Signature message validation and Signature message creation.
    @Override
    public AbstractEncodedMessage handle(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException, AKEException {
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
    private SignatureMessage handleRevealSignatureMessage(@Nonnull final Context context, @Nonnull final RevealSignatureMessage message) throws OtrCryptoException, AKEException {
        // Start validation of Reveal Signature message.
        final byte[] remotePublicKeyBytes = OtrCryptoEngine.aesDecrypt(message.revealedKey, null, this.remotePublicKeyEncrypted);
        final byte[] expectedRemotePublicKeyHash = OtrCryptoEngine.sha256Hash(remotePublicKeyBytes);
        OtrCryptoEngine.checkEquals(this.remotePublicKeyHash, expectedRemotePublicKeyHash, "Remote's public key hash failed validation.");
        final BigInteger remotePublicKeyMPI;
        try {
            remotePublicKeyMPI = SerializationUtils.readMpi(remotePublicKeyBytes);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to deserialize remote public key bytes.", ex);
        }
        final DHPublicKey remoteDHPublicKey = OtrCryptoEngine.getDHPublicKey(remotePublicKeyMPI);
        final SharedSecret s = OtrCryptoEngine.generateSecret(this.keypair.getPrivate(), remoteDHPublicKey);
        final byte[] remoteXEncryptedBytes = SerializationUtils.writeData(message.xEncrypted);
        final byte[] expectedXEncryptedMAC = OtrCryptoEngine.sha256Hmac160(remoteXEncryptedBytes, s.m2());
        OtrCryptoEngine.checkEquals(message.xEncryptedMAC, expectedXEncryptedMAC, "xEncryptedMAC failed validation.");
        final byte[] remoteMysteriousXBytes = OtrCryptoEngine.aesDecrypt(s.c(), null, message.xEncrypted);
        final SignatureX remoteMysteriousX;
        try {
            remoteMysteriousX = SerializationUtils.toMysteriousX(remoteMysteriousXBytes);
        } catch (final IOException ex) {
            throw new IllegalStateException("Failed to deserialize signature message.", ex);
        }
        final SignatureM expectedM = new SignatureM(remoteDHPublicKey,
                (DHPublicKey) this.keypair.getPublic(),
                remoteMysteriousX.longTermPublicKey, remoteMysteriousX.dhKeyID);
        final byte[] expectedMBytes = SerializationUtils.toByteArray(expectedM);
        final byte[] expectedSignature = OtrCryptoEngine.sha256Hmac(expectedMBytes, s.m1());
        OtrCryptoEngine.verify(expectedSignature, remoteMysteriousX.longTermPublicKey,
                remoteMysteriousX.signature);
        LOGGER.finest("Signature verification succeeded.");
        // Start construction of Signature message.
        // FIXME have this keypair in field ... did we already use it before because then it's probably better to avoid risk of getting a different local keypair from context.
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
                localLongTermKeyPair, this.keypair,
                remoteMysteriousX.longTermPublicKey, remoteDHPublicKey, s);
        context.secure(params);
        // TODO consider putting setState in try-finally to ensure that we transition back to NONE once done.
        context.setState(new StateInitial());
        // FIXME Clear any temporary AKE data that is remaining.
        return signatureMessage;
    }
}
