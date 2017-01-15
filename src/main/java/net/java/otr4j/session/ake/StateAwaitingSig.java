package net.java.otr4j.session.ake;

import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
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

final class StateAwaitingSig implements State {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingSig.class.getCanonicalName());

    private final int version;
    // TODO check if this is actually used/needed. Otherwise clean it up. (Not sure if needed in SecurityParameters.)
    private final KeyPair localLongTermKeyPair;
    private final KeyPair localDHKeyPair;
    private final DHPublicKey remoteDHPublicKey;
    private final SharedSecret s;

    /**
     * Saved copy of the Reveal Signature Message for retransmission in case we
     * receive a DH Key message with the exact same DH public key.
     */
    private final RevealSignatureMessage previousRevealSigMessage;

    StateAwaitingSig(final int version,
            @Nonnull final KeyPair localLongTermKeyPair,
            @Nonnull final KeyPair localDHKeyPair,
            @Nonnull final DHPublicKey remoteDHPublicKey,
            @Nonnull final SharedSecret s,
            @Nonnull final RevealSignatureMessage previousRevealSigMessage) {
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unsupported version specified");
        }
        this.version = version;
        // FIXME validate non-null, keypair for local longterm key pair
        this.localLongTermKeyPair = Objects.requireNonNull(localLongTermKeyPair);
        // FIXME validate non-null, keypair
        this.localDHKeyPair = Objects.requireNonNull(localDHKeyPair);
        // FIXME validate non-null, DH public key
        this.remoteDHPublicKey = Objects.requireNonNull(remoteDHPublicKey);
        // FIXME verify shared secret s
        this.s = Objects.requireNonNull(s);
        // FIXME verify reveal sig message?
        this.previousRevealSigMessage = Objects.requireNonNull(previousRevealSigMessage);
    }

    @Override
    public DHCommitMessage initiate(Context context, int version) {
        // FIXME implement
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public AbstractEncodedMessage handle(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException, AKEException {
        if (message instanceof DHCommitMessage) {
            final DHCommitMessage commitMessage = (DHCommitMessage) message;
            final KeyPair newKeypair = generateKeyPair(context.secureRandom());
            // FIXME set version in session?
            LOGGER.finest("Ignoring AWAITING_SIG state and sending a new DH key message.");
            context.setState(new StateAwaitingRevealSig(commitMessage.protocolVersion, newKeypair, commitMessage.dhPublicKeyHash, commitMessage.dhPublicKeyEncrypted));
            return new DHKeyMessage(commitMessage.protocolVersion, (DHPublicKey) newKeypair.getPublic(), context.senderInstance(), context.receiverInstance());
        }
        if (version != this.version) {
            // FIXME go with unchecked exception here?
            throw new IllegalArgumentException("unexpected version");
        }
        if (message instanceof DHKeyMessage) {
            final DHKeyMessage keyMessage = (DHKeyMessage) message;
            if (!((DHPublicKey) this.localDHKeyPair.getPublic()).getY().equals(keyMessage.dhPublicKey.getY())) {
                LOGGER.info("DHKeyMessage contains different DH public key. Ignoring message.");
                return null;
            }
            return this.previousRevealSigMessage;
        } else if (message instanceof SignatureMessage) {
            final SignatureMessage sigMessage = (SignatureMessage) message;
            final byte[] xEncryptedBytes;
            try {
                xEncryptedBytes = SerializationUtils.writeData(sigMessage.xEncrypted);
            } catch (final IOException ex) {
                throw new IllegalStateException("Failed to serialize xEncrypted from signature message.", ex);
            }
            final byte[] xEncryptedMAC;
            try {
                xEncryptedMAC = OtrCryptoEngine.sha256Hmac160(xEncryptedBytes, s.m2p());
            } catch (final OtrCryptoException ex) {
                throw new IllegalStateException("Failed to calculate MAC of xEncryptedBytes.", ex);
            }
            if (!Arrays.equals(xEncryptedMAC, sigMessage.xEncryptedMAC)) {
                throw new IllegalStateException("Failed validation of xEncryptedMAC.");
            }
            final byte[] remoteXBytes;
            try {
                remoteXBytes = OtrCryptoEngine.aesDecrypt(s.cp(), null, sigMessage.xEncrypted);
            } catch (final OtrCryptoException ex) {
                throw new IllegalStateException("Failed to decrypt xEncrypted.", ex);
            }
            final SignatureX remoteX;
            try {
                remoteX = SerializationUtils.toMysteriousX(remoteXBytes);
            } catch (final IOException | OtrCryptoException ex) {
                throw new IllegalStateException("Failed to serialize MysteriousX.", ex);
            }
            final SignatureM remoteM = new SignatureM(this.remoteDHPublicKey, (DHPublicKey) this.localDHKeyPair.getPublic(), remoteX.longTermPublicKey, remoteX.dhKeyID);
            final byte[] remoteMBytes;
            try {
                remoteMBytes = SerializationUtils.toByteArray(remoteM);
            } catch (final IOException ex) {
                throw new IllegalStateException("Failed to serialize remoteM message.", ex);
            }
            final byte[] expectedSignature;
            try {
                expectedSignature = OtrCryptoEngine.sha256Hmac(remoteMBytes, s.m1p());
            } catch (final OtrCryptoException ex) {
                throw new IllegalStateException("Failed to calculate sha256 HMAC of remoteMBytes.", ex);
            }
            OtrCryptoEngine.verify(expectedSignature, remoteX.longTermPublicKey, remoteX.signature);
            // Transition to ENCRYPTED session state.
            final SecurityParameters params = new SecurityParameters(
                    this.version, this.localLongTermKeyPair, this.localDHKeyPair,
                    remoteX.longTermPublicKey, remoteDHPublicKey, this.s);
            context.secure(params);
            // TODO consider putting setState in try-finally to ensure that we transition back to NONE once done.
            context.setState(new StateInitial());
        }
        throw new IllegalStateException("Unexpected message type received.");
    }

    // TODO this method is not necessary here ... it should be a utility method.
    private KeyPair generateKeyPair(@Nonnull final SecureRandom secureRandom) {
        try {
            final KeyPair generatedKeyPair = OtrCryptoEngine.generateDHKeyPair(secureRandom);
            LOGGER.finest("Generated local D-H key pair.");
            return generatedKeyPair;
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to generate DH keypair.", ex);
        }
    }

}
