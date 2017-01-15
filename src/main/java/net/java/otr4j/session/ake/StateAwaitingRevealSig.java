package net.java.otr4j.session.ake;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
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

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingRevealSig.class.getCanonicalName());

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
        // FIXME implement
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    // FIXME current implementation has risk of mixing up variables from Reveal Signature message validation and Signature message creation.
    @Override
    public AbstractEncodedMessage handle(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException, AKEException {
        if (message instanceof DHCommitMessage) {
            final DHCommitMessage commitMessage = (DHCommitMessage) message;
            context.setState(new StateAwaitingRevealSig(commitMessage.protocolVersion, this.keypair, commitMessage.dhPublicKeyHash, commitMessage.dhPublicKeyEncrypted));
            return new DHKeyMessage(commitMessage.protocolVersion, (DHPublicKey) this.keypair.getPublic(), context.senderInstance(), context.receiverInstance());
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
        final RevealSignatureMessage revealSigMessage = (RevealSignatureMessage) message;
        // Start validation of Reveal Signature message.
        final byte[] remotePublicKeyBytes;
        try {
            remotePublicKeyBytes = OtrCryptoEngine.aesDecrypt(revealSigMessage.revealedKey, null, this.remotePublicKeyEncrypted);
        } catch (OtrCryptoException ex) {
            // FIXME convert to checked exception
            throw new IllegalStateException("Failed to decrypt the public key.", ex);
        }
        final byte[] expectedRemotePublicKeyHash = OtrCryptoEngine.sha256Hash(remotePublicKeyBytes);
        if (!Arrays.equals(this.remotePublicKeyHash, expectedRemotePublicKeyHash)) {
            LOGGER.finest("Hashes do not match. Ignoring this Reveal Signature message.");
            // FIXME convert to checked exception
            // FIXME ignore message?
            throw new IllegalStateException("Invalid public key hash for remote public key bytes.");
        }
        final BigInteger remotePublicKeyMPI;
        try {
            remotePublicKeyMPI = SerializationUtils.readMpi(remotePublicKeyBytes);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to deserialize remote public key bytes.", ex);
        }
        final DHPublicKey remoteDHPublicKey;
        try {
            remoteDHPublicKey = OtrCryptoEngine.getDHPublicKey(remotePublicKeyMPI);
        } catch (OtrCryptoException ex) {
            throw new IllegalStateException("Failed to create remote public key from bytes.", ex);
        }
        final SharedSecret s;
        try {
            s = OtrCryptoEngine.generateSecret(this.keypair.getPrivate(), remoteDHPublicKey);
        } catch (OtrCryptoException ex) {
            throw new IllegalStateException("Failed to generate shared secret s.", ex);
        }
        final byte[] remoteXEncryptedBytes;
        try {
            remoteXEncryptedBytes = SerializationUtils.writeData(revealSigMessage.xEncrypted);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to write signature as data.", ex);
        }
        final byte[] expectedXEncryptedMAC;
        try {
            expectedXEncryptedMAC = OtrCryptoEngine.sha256Hmac160(remoteXEncryptedBytes, s.m2());
        } catch (OtrCryptoException ex) {
            throw new IllegalStateException("Failed to calculate hash of signature bytes to use for verification.", ex);
        }
        // FIXME replace with static method that throws checked exception in case of failure.
        if (!Arrays.equals(revealSigMessage.xEncryptedMAC, expectedXEncryptedMAC)) {
            throw new IllegalStateException("Failed verification of signature hash.");
        }
        final byte[] remoteMysteriousXBytes;
        try {
            remoteMysteriousXBytes = OtrCryptoEngine.aesDecrypt(s.c(), null, revealSigMessage.xEncrypted);
        } catch (OtrCryptoException ex) {
            throw new IllegalStateException("Failed to decrypt encrypted signature.", ex);
        }
        final SignatureX remoteMysteriousX;
        try {
            remoteMysteriousX = SerializationUtils.toMysteriousX(remoteMysteriousXBytes);
        } catch (IOException | OtrCryptoException ex) {
            throw new IllegalStateException("Failed to deserialize signature message.", ex);
        }
        final SignatureM expectedM = new SignatureM(remoteDHPublicKey,
                (DHPublicKey) this.keypair.getPublic(),
                remoteMysteriousX.longTermPublicKey, remoteMysteriousX.dhKeyID);
        final byte[] expectedMBytes;
        try {
            expectedMBytes = SerializationUtils.toByteArray(expectedM);
        } catch (final IOException ex) {
            throw new IllegalStateException("Failed to serialize expected SignatureM message.", ex);
        }
        final byte[] expectedSignature;
        try {
            expectedSignature = OtrCryptoEngine.sha256Hmac(expectedMBytes, s.m1());
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to generate expected signature for remote SignatureM message.", ex);
        }
        OtrCryptoEngine.verify(expectedSignature, remoteMysteriousX.longTermPublicKey,
                remoteMysteriousX.signature);
        LOGGER.finest("Signature verification succeeded.");
        // Start construction of Signature message.
        // FIXME have this keypair in field ... did we already use it before because then it's probably better to avoid risk of getting a different local keypair from context.
        final KeyPair localLongTermKeyPair = context.longTermKeyPair();
        final SignatureM signatureM = new SignatureM(
                (DHPublicKey) this.keypair.getPublic(), remoteDHPublicKey,
                localLongTermKeyPair.getPublic(), LOCAL_DH_PRIVATE_KEY_ID);
        final byte[] signatureMBytes;
        try {
            signatureMBytes = SerializationUtils.toByteArray(signatureM);
        } catch (final IOException ex) {
            throw new IllegalStateException("Failed to serialize SignatureM message to be included in Signature response message.", ex);
        }
        final byte[] mhash;
        try {
            mhash = OtrCryptoEngine.sha256Hmac(signatureMBytes, s.m1p());
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to calculate sha256Hmac of signatureMBytes.", ex);
        }
        final byte[] signature;
        try {
            signature = OtrCryptoEngine.sign(mhash, localLongTermKeyPair.getPrivate());
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to calculate signature of signatureM message.", ex);
        }
        final SignatureX mysteriousX = new SignatureX(localLongTermKeyPair.getPublic(),
                LOCAL_DH_PRIVATE_KEY_ID, signature);
        final byte[] xEncrypted;
        try {
            xEncrypted = OtrCryptoEngine.aesEncrypt(s.cp(), null,
                    SerializationUtils.toByteArray(mysteriousX));
        } catch (final IOException | OtrCryptoException ex) {
            throw new IllegalStateException("Failed to serialize SignatureX.", ex);
        }
        final byte[] xEncryptedBytes;
        try {
            xEncryptedBytes = SerializationUtils.writeData(xEncrypted);
        } catch (final IOException ex) {
            throw new IllegalStateException("Failed to serialize xEncrypted.", ex);
        }
        final byte[] xEncryptedHash;
        try {
            xEncryptedHash = OtrCryptoEngine.sha256Hmac160(xEncryptedBytes, s.m2p());
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to calculate sha256Hmac of xEncrypted.", ex);
        }
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
