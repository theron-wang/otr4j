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

/**
 * AKE state Awaiting Signature message, a.k.a. AUTHSTATE_AWAITING_SIG.
 *
 * @author Danny van Heumen
 */
final class StateAwaitingSig extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingSig.class.getName());

    private final int version;
    private final KeyPair localDHKeyPair;
    private final DHPublicKey remoteDHPublicKey;
    private final SharedSecret s;

    /**
     * Saved copy of the Reveal Signature Message for retransmission in case we
     * receive a DH Key message with the exact same DH public key.
     */
    private final RevealSignatureMessage previousRevealSigMessage;

    StateAwaitingSig(final int version,
            @Nonnull final KeyPair localDHKeyPair,
            @Nonnull final DHPublicKey remoteDHPublicKey,
            @Nonnull final SharedSecret s,
            @Nonnull final RevealSignatureMessage previousRevealSigMessage) {
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unsupported version specified");
        }
        this.version = version;
        this.localDHKeyPair = Objects.requireNonNull(localDHKeyPair);
        try {
            this.remoteDHPublicKey = OtrCryptoEngine.verify(remoteDHPublicKey);
        } catch (final OtrCryptoException ex) {
            throw new IllegalArgumentException("Illegal D-H Public Key provided.", ex);
        }
        this.s = Objects.requireNonNull(s);
        this.previousRevealSigMessage = Objects.requireNonNull(previousRevealSigMessage);
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
            return handleDHKeyMessage((DHKeyMessage) message);
        } else if (message instanceof SignatureMessage) {
            return handleSignatureMessage(context, (SignatureMessage) message);
        } else {
            // FIXME should we error out or ignore?
            throw new IllegalStateException("Unexpected message type received.");
        }
    }

    @Override
    public int getVersion() {
        return this.version;
    }

    @Nonnull
    private DHKeyMessage handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) {
        LOGGER.finest("Generating local D-H key pair.");
        final KeyPair newKeypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
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

    private SignatureMessage handleSignatureMessage(@Nonnull final AuthContext context, @Nonnull final SignatureMessage message)
            throws OtrCryptoException, AuthContext.InteractionFailedException, IOException {
        try {
            final byte[] xEncryptedBytes = SerializationUtils.writeData(message.xEncrypted);
            final byte[] xEncryptedMAC = OtrCryptoEngine.sha256Hmac160(xEncryptedBytes, s.m2p());
            OtrCryptoEngine.checkEquals(xEncryptedMAC, message.xEncryptedMAC, "xEncryptedMAC failed verification.");
            final byte[] remoteXBytes = OtrCryptoEngine.aesDecrypt(s.cp(), null, message.xEncrypted);
            final SignatureX remoteX = SerializationUtils.toMysteriousX(remoteXBytes);
            final SignatureM remoteM = new SignatureM(this.remoteDHPublicKey,
                    (DHPublicKey) this.localDHKeyPair.getPublic(),
                    remoteX.longTermPublicKey, remoteX.dhKeyID);
            final byte[] remoteMBytes = SerializationUtils.toByteArray(remoteM);
            final byte[] expectedSignature = OtrCryptoEngine.sha256Hmac(remoteMBytes, s.m1p());
            OtrCryptoEngine.verify(expectedSignature, remoteX.longTermPublicKey, remoteX.signature);
            // Transition to ENCRYPTED session state.
            final SecurityParameters params = new SecurityParameters(this.version,
                    this.localDHKeyPair, remoteX.longTermPublicKey,
                    remoteDHPublicKey, this.s);
            context.secure(params);
            return null;
        } finally {
            // Ensure transition to AUTHSTATE_NONE.
            context.setState(StateInitial.instance());
        }
    }
}
