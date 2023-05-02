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
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.crypto.DSAKeyPair.DSA_SIGNATURE_LENGTH_BYTES;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class SignatureXTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DSAPublicKey publicKey = generateDSAKeyPair(RANDOM).getPublic();

    @Test(expected = NullPointerException.class)
    public void testConstructNullDSAPublicKey() {
        new SignatureX(null, 0, new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullSignature() {
        new SignatureX(publicKey, 1, null);
    }

    @Test
    public void testConstruct() {
        final byte[] signature = randomBytes(RANDOM, new byte[DSA_SIGNATURE_LENGTH_BYTES]);
        new SignatureX(publicKey, 1, signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructBadSignatureLength() {
        final byte[] signature = randomBytes(RANDOM, new byte[DSA_SIGNATURE_LENGTH_BYTES + 1]);
        new SignatureX(publicKey, 1, signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructBadDHKeyId() {
        final byte[] signature = randomBytes(RANDOM, new byte[DSA_SIGNATURE_LENGTH_BYTES]);
        new SignatureX(publicKey, 0, signature);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifySignatureNullSignature() throws OtrCryptoException {
        final byte[] signature = randomBytes(RANDOM, new byte[DSA_SIGNATURE_LENGTH_BYTES]);
        final SignatureX sig = new SignatureX(publicKey, 1, signature);
        sig.verify(null);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifySignature() throws OtrCryptoException {
        final int signatureLength = publicKey.getParams().getQ().bitLength() / 8 * 2;
        assertEquals(signatureLength, DSA_SIGNATURE_LENGTH_BYTES);
        final byte[] signature = new byte[DSA_SIGNATURE_LENGTH_BYTES];
        final BigInteger r = new BigInteger(1, randomBytes(RANDOM, new byte[signatureLength / 2]))
                .mod(publicKey.getParams().getQ());
        asUnsignedByteArray(r, signature, 0, 20);
        final BigInteger s = new BigInteger(1, randomBytes(RANDOM, new byte[signatureLength / 2]))
                .mod(publicKey.getParams().getQ());
        asUnsignedByteArray(s, signature, 20, 20);
        final SignatureX sig = new SignatureX(publicKey, 1, signature);
        final byte[] msg = randomBytes(RANDOM, new byte[50]);
        sig.verify(msg);
    }
}
