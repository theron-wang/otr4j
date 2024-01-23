/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;

/**
 * RemoteInfo contains information on the remote party of the OTR connection.
 */
// TODO consider if this is sufficient, or whether we need some sort of "general session details" type which also contains local (security) information.
public final class RemoteInfo {

    /**
     * version is the active OTR protocol version.
     */
    @Nonnull
    public final Version version;

    /**
     * publicKeyV3 contains the long-term public key (DSA) if OTR version 3 is active, or contains the legacy long-term
     * public key, in case it was part of the ClientProfile for an OTR version 4 session.
     */
    @Nullable
    public final DSAPublicKey publicKeyV3;

    /**
     * clientProfile contains the long-term public keys (identity, forging key) and legacy key, if OTR version 4 is
     * active. This represents the identity of the remote party once a secure session has been established.
     */
    @Nullable
    public final ClientProfile clientProfile;

    /**
     * Constructor for RemoteInfo.
     *
     * @param version      the active OTR protocol version
     * @param publicKeyV3  the protocol version 3 long-term public key (or OTRv4 legacy public key)
     * @param clientProfile the protocol version 4 client profile
     */
    public RemoteInfo(final Version version, @Nullable final DSAPublicKey publicKeyV3,
            @Nullable final ClientProfile clientProfile) {
        this.version = requireNonNull(version);
        this.publicKeyV3 = publicKeyV3;
        this.clientProfile = clientProfile;
    }
}
