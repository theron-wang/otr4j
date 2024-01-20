/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Collections.requireAbsent;
import static net.java.otr4j.util.Collections.requireElements;
import static net.java.otr4j.util.Collections.requireMinElements;
import static net.java.otr4j.util.Objects.requireNotEquals;

/**
 * The validated representation of the ClientProfile.
 */
// TODO consider that this client profile has no expiration date, therefore we cannot determine if it is still reliable for profiles from our known contacts. Would need management: storing, comparing, updating, purging. (There is little risk for the established session as we would get a client profile sent which must be valid.)
public final class ClientProfile {

    private static final Set<Integer> MANDATORY_VERSIONS = Set.of(Version.FOUR);

    private static final Set<Integer> FORBIDDEN_VERSIONS = Set.of(Version.ONE, Version.TWO);

    /**
     * Owner's instance tag.
     */
    @Nonnull
    private final InstanceTag instanceTag;

    /**
     * Public key of the long-term Ed448 keypair.
     */
    @Nonnull
    private final Point longTermPublicKey;

    /**
     * Public key of the Ed448 Forging key.
     */
    @Nonnull
    private final Point forgingKey;

    /**
     * List of supported versions.
     */
    @Nonnull
    private final List<Integer> versions;

    /**
     * DSA public key.
     */
    @Nullable
    private final DSAPublicKey dsaPublicKey;

    /**
     * Constructor for the client profile instance.
     *
     * @param instanceTag       The instance tag. As the instance tag is now part of the client profile, it should be
     *                          persistent such that other clients can rely on the client information for next time you
     *                          are establishing secure communications.
     * @param longTermPublicKey The long-term Ed448 public key. This is the public key of the key pair provided at
     *                          {@link OtrEngineHost#getLongTermKeyPair(SessionID)}.
     * @param forgingKey        The Ed448 Forging public key. The key can be generated using
     *                          {@link net.java.otr4j.crypto.ed448.EdDSAKeyPair#generate(java.security.SecureRandom)}.
     * @param versions          supported protocol versions
     * @param dsaPublicKey      The DSA public key. This is the public key of the key pair provided at
     *                          {@link OtrEngineHost#getLocalKeyPair(SessionID)}.
     */
    public ClientProfile(final InstanceTag instanceTag, final Point longTermPublicKey, final Point forgingKey,
            final List<Integer> versions, @Nullable final DSAPublicKey dsaPublicKey) {
        requireNotEquals(0, instanceTag.getValue(), "Zero-value instance tag is not allowed in OTRv4.");
        this.instanceTag = requireNonNull(instanceTag);
        this.longTermPublicKey = requireNonNull(longTermPublicKey);
        this.forgingKey = requireNonNull(forgingKey);
        this.versions = unmodifiableList(requireMinElements(1,
                requireElements(MANDATORY_VERSIONS, requireAbsent(FORBIDDEN_VERSIONS, versions))));
        if (this.versions.contains(Version.THREE) && dsaPublicKey == null) {
            throw new IllegalArgumentException("Support for OTR version 3 requires that a DSA public key is provided.");
        }
        this.dsaPublicKey = dsaPublicKey;
    }

    /**
     * Get the instance tag.
     *
     * @return Returns the instance tag.
     */
    @Nonnull
    public InstanceTag getInstanceTag() {
        return this.instanceTag;
    }

    /**
     * Get the long-term Ed448 public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getLongTermPublicKey() {
        return this.longTermPublicKey;
    }

    /**
     * Get the Forging public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getForgingKey() {
        return this.forgingKey;
    }

    /**
     * Get the supported OTR protocol versions.
     *
     * @return Returns the versions.
     */
    @Nonnull
    public List<Integer> getVersions() {
        return this.versions;
    }

    /**
     * The long-term DSA public key. (Used in OTRv3.)
     *
     * @return Returns the public key.
     */
    @Nullable
    public DSAPublicKey getDsaPublicKey() {
        return this.dsaPublicKey;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ClientProfile that = (ClientProfile) o;
        return Objects.equals(this.instanceTag, that.instanceTag)
                && Objects.equals(this.longTermPublicKey, that.longTermPublicKey)
                && Objects.equals(this.forgingKey, that.forgingKey)
                && Objects.equals(this.versions, that.versions)
                && Objects.equals(this.dsaPublicKey, that.dsaPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.instanceTag, this.longTermPublicKey, this.forgingKey, this.versions, this.dsaPublicKey);
    }
}
