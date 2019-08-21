/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;

/**
 * Utility class for ECDH key pair instances.
 */
public final class ECDHKeyPairs {

    private ECDHKeyPairs() {
        // No need to instantiate utility class.
    }

    /**
     * Verify a ECDH public key.
     *
     * @param point The ECDH public key.
     * @throws ValidationException In case of illegal point value.
     */
    public static void verifyECDHPublicKey(final Point point) throws ValidationException {
        if (!containsPoint(point)) {
            throw new ValidationException("Public key is not on curve Ed448-Goldilocks.");
        }
    }
}
