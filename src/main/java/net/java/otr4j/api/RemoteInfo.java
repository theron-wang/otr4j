package net.java.otr4j.api;

import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;

/**
 * RemoteInfo contains information on the remote party of the OTR connection.
 */
public final class RemoteInfo {

    /**
     * version is the active OTR protocol version.
     */
    public final int version;

    /**
     * publicKeyV3 contains the long-term public key (DSA) if OTR version 3 is active.
     */
    @Nullable
    public final DSAPublicKey publicKeyV3;

    /**
     * publicKeyV4 contains the long-term public key (Ed448) if OTR version 4 is active.
     */
    @Nullable
    public final Point publicKeyV4;

    /**
     * forgingKeyV4 contains the forging public key (Ed448) if OTR version 4 is active.
     */
    @Nullable
    public final Point forgingKeyV4;

    /**
     * Constructor for RemoteInfo.
     *
     * @param version      the active OTR protocol version
     * @param publicKeyV3  the protocol version 3 long-term public key
     * @param publicKeyV4  the protocol version 4 long-term public key
     * @param forgingKeyV4 the protocol version 4 forging key
     */
    public RemoteInfo(final int version, @Nullable final DSAPublicKey publicKeyV3, @Nullable final Point publicKeyV4,
            @Nullable final Point forgingKeyV4) {
        this.version = version;
        this.publicKeyV3 = publicKeyV3;
        this.publicKeyV4 = publicKeyV4;
        // FIXME let forging key to internal-only, i.e. auto-generated and not exposed?
        this.forgingKeyV4 = forgingKeyV4;
    }
}
