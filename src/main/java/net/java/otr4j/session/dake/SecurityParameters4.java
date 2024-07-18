/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.dake;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.session.state.DoubleRatchet;

import static net.java.otr4j.util.Objects.requireNonNull;

/**
 * OTRv4 security parameters for the newly established OTRv4 secure session.
 */
public final class SecurityParameters4 {

    /**
     * The session's derived SSID.
     */
    public final byte[] ssid;

    /**
     * The established shared (but mirrored) double-ratchet. 
     */
    public final DoubleRatchet ratchet;

    /**
     * Our own long-term (identity) public key as established during DAKE.
     */
    public final Point longTermKey;

    /**
     * Our own forging key as established during DAKE.
     */
    public final Point forgingKey;

    /**
     * The other party's (validated) client-profile.
     */
    public final ClientProfile other;

    SecurityParameters4(final byte[] ssid, final DoubleRatchet ratchet, final Point longTermKey, final Point forgingKey, final ClientProfile other) {
        this.ssid = requireNonNull(ssid);
        this.ratchet = requireNonNull(ratchet);
        this.longTermKey = requireNonNull(longTermKey);
        this.forgingKey = requireNonNull(forgingKey);
        this.other = requireNonNull(other);
    }
}
