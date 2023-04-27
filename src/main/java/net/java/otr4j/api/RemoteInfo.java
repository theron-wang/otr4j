package net.java.otr4j.api;

import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;

public final class RemoteInfo {

    public final int version;

    @Nullable
    public final DSAPublicKey publicKeyV3;

    @Nullable
    public final Point publicKeyV4;

    @Nullable
    public final Point forgingKeyV4;

    public RemoteInfo(int version, @Nullable final DSAPublicKey publicKeyV3, @Nullable final Point publicKeyV4, @Nullable final Point forgingKeyV4) {
        this.version = version;
        this.publicKeyV3 = publicKeyV3;
        this.publicKeyV4 = publicKeyV4;
        this.forgingKeyV4 = forgingKeyV4;
    }
}
