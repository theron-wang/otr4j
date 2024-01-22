/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;

/**
 * Utilities for SignatureX.
 */
public final class SignatureXs {

    private SignatureXs() {
        // No need to instantiate utility class.
    }

    /**
     * Read Signature X signature data.
     *
     * @param bytes The bytes representing a SignatureX, to be read.
     * @return Returns Signature X instance.
     * @throws ProtocolException        In case of failure in reading the message.
     * @throws OtrCryptoException       In case of failures while processing the message content.
     */
    @SuppressWarnings("PMD.PrematureDeclaration")
    @Nonnull
    public static SignatureX readSignatureX(final byte[] bytes) throws ProtocolException, OtrCryptoException {
        final OtrInputStream in = new OtrInputStream(bytes);
        final DSAPublicKey pubKey = in.readPublicKey();
        final int dhKeyID = in.readInt();
        if (dhKeyID == 0) {
            throw new ProtocolException("Illegal DH key ID encountered. Must be > 0, but was " + dhKeyID);
        }
        final byte[] sig = in.readSignature();
        return new SignatureX(pubKey, dhKeyID, sig);
    }
}
