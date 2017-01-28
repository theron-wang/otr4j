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

/**
 * AKE state Awaiting Reveal Signature message, a.k.a.
 * AUTHSTATE_AWAITING_REVEALSIG.
 *
 * @author Danny van Heumen
 */
final class StateAwaitingRevealSig extends AbstractAuthState {

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
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message)
            throws OtrCryptoException, AuthContext.InteractionFailedException, IOException {
        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (message.protocolVersion != this.version) {
            throw new IllegalArgumentException("unexpected version");
        }
        if (message instanceof DHKeyMessage) {
            LOGGER.log(Level.INFO, "Ignoring DHKey message.");
            return null;
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
    private DHKeyMessage handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) {
        context.setState(new StateAwaitingRevealSig(message.protocolVersion, this.keypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
        return new DHKeyMessage(message.protocolVersion, (DHPublicKey) this.keypair.getPublic(), context.senderInstance(), context.receiverInstance());
    }

    /**
     * Validate the received Reveal Signature message and construct the
     * Signature message to respond with.
     *
     * @param context Authentication context.
     * @param message Received Reveal Signature message.
     * @return Returns Signature message.
     * @throws OtrCryptoException Thrown in case of exceptions during validation
     * or signature message creation.
     * @throws net.java.otr4j.session.ake.AuthContext.InteractionFailedException
     * Thrown in case of interaction failure with the provided context.
     * @throws IOException Thrown in case of message content errors.
     */
    @Nonnull
    private SignatureMessage handleRevealSignatureMessage(@Nonnull final AuthContext context, @Nonnull final RevealSignatureMessage message)
            throws OtrCryptoException, AuthContext.InteractionFailedException, IOException {
        final DHPublicKey remoteDHPublicKey;
        final SharedSecret s;
        final SignatureX remoteMysteriousX;
        try {
            // Start validation of Reveal Signature message.
            final byte[] remotePublicKeyBytes = OtrCryptoEngine.aesDecrypt(message.revealedKey, null, this.remotePublicKeyEncrypted);
            final byte[] expectedRemotePublicKeyHash = OtrCryptoEngine.sha256Hash(remotePublicKeyBytes);
            OtrCryptoEngine.checkEquals(this.remotePublicKeyHash, expectedRemotePublicKeyHash, "Remote's public key hash failed validation.");
            final BigInteger remotePublicKeyMPI = SerializationUtils.readMpi(remotePublicKeyBytes);
            remoteDHPublicKey = OtrCryptoEngine.verify(
                    OtrCryptoEngine.getDHPublicKey(remotePublicKeyMPI));
            s = OtrCryptoEngine.generateSecret(this.keypair.getPrivate(), remoteDHPublicKey);
            final byte[] remoteXEncryptedBytes = SerializationUtils.writeData(message.xEncrypted);
            final byte[] expectedXEncryptedMAC = OtrCryptoEngine.sha256Hmac160(remoteXEncryptedBytes, s.m2());
            OtrCryptoEngine.checkEquals(message.xEncryptedMAC, expectedXEncryptedMAC, "xEncryptedMAC failed validation.");
            final byte[] remoteMysteriousXBytes = OtrCryptoEngine.aesDecrypt(s.c(), null, message.xEncrypted);
            remoteMysteriousX = SerializationUtils.toMysteriousX(remoteMysteriousXBytes);
            final SignatureM expectedM = new SignatureM(remoteDHPublicKey,
                    (DHPublicKey) this.keypair.getPublic(),
                    remoteMysteriousX.longTermPublicKey, remoteMysteriousX.dhKeyID);
            final byte[] expectedMBytes = SerializationUtils.toByteArray(expectedM);
            final byte[] expectedSignature = OtrCryptoEngine.sha256Hmac(expectedMBytes, s.m1());
            OtrCryptoEngine.verify(expectedSignature, remoteMysteriousX.longTermPublicKey,
                    remoteMysteriousX.signature);
            LOGGER.finest("Signature verification succeeded.");
        } finally {
            // Ensure transition to AUTHSTATE_NONE.
            context.setState(StateInitial.instance());
        }
        // Transition to ENCRYPTED message state.
        final SecurityParameters params = new SecurityParameters(this.version,
                this.keypair, remoteMysteriousX.longTermPublicKey,
                remoteDHPublicKey, s);
        context.secure(params);
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
        LOGGER.finest("Creating signature message for response.");
        return new SignatureMessage(this.version, xEncrypted, xEncryptedHash,
                context.senderInstance(), context.receiverInstance());
    }
}
