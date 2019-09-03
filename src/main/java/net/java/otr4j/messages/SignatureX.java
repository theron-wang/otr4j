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
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;
import org.bouncycastle.util.Arrays;

import javax.annotation.Nonnull;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.DSAKeyPair.DSA_SIGNATURE_LENGTH_BYTES;
import static net.java.otr4j.crypto.DSAKeyPair.verifySignature;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.Integers.requireNotEquals;

/**
 * The payload representing the X value.
 *
 * @author George Politis
 */
public final class SignatureX implements OtrEncodable {

    @Nonnull
    private final DSAPublicKey longTermPublicKey;

    private final int dhKeyID;

    @Nonnull
    private final byte[] signature;

    /**
     * Constructor.
     *
     * @param ourLongTermPublicKey our long-term DSA public key
     * @param ourKeyID             our key ID
     * @param signature            the corresponding signature
     */
    public SignatureX(final DSAPublicKey ourLongTermPublicKey, final int ourKeyID, final byte[] signature) {
        this.longTermPublicKey = requireNonNull(ourLongTermPublicKey);
        this.dhKeyID = requireNotEquals(0, ourKeyID);
        this.signature = requireLengthExactly(DSA_SIGNATURE_LENGTH_BYTES, signature);
        assert !allZeroBytes(this.signature)
                : "Expected non-zero bytes for signature. This may indicate that a critical bug is present, or it may be a false warning.";
    }

    /**
     * Get the long-term DSA public key.
     *
     * @return the long-term DSA public key.
     */
    @Nonnull
    public DSAPublicKey getLongTermPublicKey() {
        return longTermPublicKey;
    }

    /**
     * Get DH key id.
     *
     * @return Returns the DH key ID.
     */
    public int getDhKeyID() {
        return dhKeyID;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + dhKeyID;
        result = prime * result + longTermPublicKey.hashCode();
        result = prime * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final SignatureX other = (SignatureX) obj;
        if (dhKeyID != other.dhKeyID) {
            return false;
        }
        if (!longTermPublicKey.equals(other.longTermPublicKey)) {
            return false;
        }
        return constantTimeEquals(signature, other.signature);
    }

    /**
     * Verify expected signature with signature in SignatureX.
     *
     * @param expectedSignature the expected signature to verify against the SignatureX signature
     * @throws OtrCryptoException In case of failures of a cryptographic nature.
     */
    public void verify(final byte[] expectedSignature) throws OtrCryptoException {
        verifySignature(expectedSignature, this.longTermPublicKey, this.signature);
    }

    @Override
    public void writeTo(final OtrOutputStream out) {
        out.writePublicKey(this.longTermPublicKey);
        out.writeInt(this.dhKeyID);
        out.writeDSASignature(this.signature);
    }
}
