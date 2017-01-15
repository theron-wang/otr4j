package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.SharedSecret;

/**
 * Container that stores all the security parameters that were negotiated during
 * AKE. These parameters are passed on to initiate the encrypted message state.
 *
 * @author Danny van Heumen
 */
// FIXME needs a few tests just-in-case.
public final class SecurityParameters {

    private final int version;
    private final KeyPair localLongTermKeyPair;
    private final KeyPair localDHKeyPair;
    private final PublicKey remoteLongTermPublicKey;
    private final DHPublicKey remoteDHPublicKey;
    private final SharedSecret s;

    SecurityParameters(final int version, @Nonnull final KeyPair localLongTermKeyPair, @Nonnull final KeyPair localDHKeyPair, @Nonnull final PublicKey remoteLongTermPublicKey, @Nonnull final DHPublicKey remoteDHPublicKey, @Nonnull final SharedSecret s) {
        this.version = version;
        this.localLongTermKeyPair = Objects.requireNonNull(localLongTermKeyPair);
        this.localDHKeyPair = Objects.requireNonNull(localDHKeyPair);
        this.remoteLongTermPublicKey = Objects.requireNonNull(remoteLongTermPublicKey);
        this.remoteDHPublicKey = Objects.requireNonNull(remoteDHPublicKey);
        this.s = Objects.requireNonNull(s);
    }

    public int getVersion() {
        return version;
    }

    // TODO check if this is actually used/needed. Otherwise clean it up.
    @Nonnull
    public KeyPair getLocalLongTermKeyPair() {
        return localLongTermKeyPair;
    }

    @Nonnull
    public KeyPair getLocalDHKeyPair() {
        return localDHKeyPair;
    }

    @Nonnull
    public PublicKey getRemoteLongTermPublicKey() {
        return remoteLongTermPublicKey;
    }

    @Nonnull
    public DHPublicKey getRemoteDHPublicKey() {
        return remoteDHPublicKey;
    }

    @Nonnull
    public SharedSecret getS() {
        return s;
    }
}
