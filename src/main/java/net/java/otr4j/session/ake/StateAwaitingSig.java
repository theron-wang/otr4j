package net.java.otr4j.session.ake;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Objects;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
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

    @Override
    public AbstractEncodedMessage handle(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException, AKEException {
        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (version != this.version) {
            // FIXME go with unchecked exception here?
            throw new IllegalArgumentException("unexpected version");
        }
        if (message instanceof DHKeyMessage) {
            return handleDHKeyMessage((DHKeyMessage) message);
        } else if (message instanceof SignatureMessage) {
            return handleSignatureMessage(context, (SignatureMessage) message);
        } else {
            throw new IllegalStateException("Unexpected message type received.");
        }
    }

    @Override
    public int getVersion() {
        return this.version;
    }

    @Nonnull
    private DHKeyMessage handleDHCommitMessage(@Nonnull final Context context, @Nonnull final DHCommitMessage message) {
        LOGGER.finest("Generating local D-H key pair.");
        final KeyPair newKeypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        // FIXME set version in session?
        LOGGER.finest("Ignoring AWAITING_SIG state and sending a new DH key message.");
        context.setState(new StateAwaitingRevealSig(message.protocolVersion, newKeypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
        return new DHKeyMessage(message.protocolVersion, (DHPublicKey) newKeypair.getPublic(), context.senderInstance(), context.receiverInstance());
    }

    @Nullable
    private RevealSignatureMessage handleDHKeyMessage(@Nonnull final DHKeyMessage message) {
        if (!((DHPublicKey) this.localDHKeyPair.getPublic()).getY().equals(message.dhPublicKey.getY())) {
            // DH keypair is not the same as local pair, this message is either
            // fake or not intended for this session.
            LOGGER.info("DHKeyMessage contains different DH public key. Ignoring message.");
            return null;
        }
        // DH keypair is the same, so other side apparently didn't receive our
        // first reveal signature message, let's send the message again.
        return this.previousRevealSigMessage;
    }

    private SignatureMessage handleSignatureMessage(@Nonnull final Context context, @Nonnull final SignatureMessage message) throws AKEException, OtrCryptoException {
        final byte[] xEncryptedBytes = SerializationUtils.writeData(message.xEncrypted);
        final byte[] xEncryptedMAC = OtrCryptoEngine.sha256Hmac160(xEncryptedBytes, s.m2p());
        OtrCryptoEngine.checkEquals(xEncryptedMAC, message.xEncryptedMAC, "xEncryptedMAC failed verification.");
        final byte[] remoteXBytes = OtrCryptoEngine.aesDecrypt(s.cp(), null, message.xEncrypted);
        final SignatureX remoteX;
        try {
            remoteX = SerializationUtils.toMysteriousX(remoteXBytes);
        } catch (final IOException ex) {
            throw new IllegalStateException("Failed to deserialize MysteriousX.", ex);
        }
        final SignatureM remoteM = new SignatureM(this.remoteDHPublicKey,
                (DHPublicKey) this.localDHKeyPair.getPublic(),
                remoteX.longTermPublicKey, remoteX.dhKeyID);
        final byte[] remoteMBytes = SerializationUtils.toByteArray(remoteM);
        final byte[] expectedSignature = OtrCryptoEngine.sha256Hmac(remoteMBytes, s.m1p());
        OtrCryptoEngine.verify(expectedSignature, remoteX.longTermPublicKey, remoteX.signature);
        // Transition to ENCRYPTED session state.
        final SecurityParameters params = new SecurityParameters(
                this.version, this.localLongTermKeyPair, this.localDHKeyPair,
                remoteX.longTermPublicKey, remoteDHPublicKey, this.s);
        context.secure(params);
        // TODO consider putting setState in try-finally to ensure that we transition back to NONE once done.
        context.setState(new StateInitial());
        return null;
    }
}
