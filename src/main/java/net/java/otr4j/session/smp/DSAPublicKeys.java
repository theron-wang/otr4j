/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.smp;

import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.crypto.OtrCryptoEngine.sha1Hash;

/**
 * Utilities for DSAPublicKey.
 */
public final class DSAPublicKeys {

    private DSAPublicKeys() {
        // No need to instantiate utility class.
    }

    /**
     * Fingerprint DSA public key.
     *
     * @param publicKey the DSA public key
     * @return Returns the fingerprint as bytes.
     */
    @Nonnull
    public static byte[] fingerprint(final DSAPublicKey publicKey) {
        final byte[] bRemotePubKey = new OtrOutputStream().writePublicKey(publicKey).toByteArray();
        final byte[] trimmed = new byte[bRemotePubKey.length - 2];
        System.arraycopy(bRemotePubKey, 2, trimmed, 0, trimmed.length);
        return sha1Hash(trimmed);
    }
}
