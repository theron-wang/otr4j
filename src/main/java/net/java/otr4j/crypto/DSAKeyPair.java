/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine.convertSignatureASN1ToP1363;
import static net.java.otr4j.crypto.OtrCryptoEngine.convertSignatureP1363ToASN1;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * Key pair to keep DSA private and corresponding public key.
 */
@SuppressWarnings("InsecureCryptoUsage")
public final class DSAKeyPair {

    private static final String ALGORITHM_DSA = "DSA";
    private static final int DSA_KEY_LENGTH_BITS = 1024;

    private static final String ALGORITHM_DSA_SIGNATURE = "NONEwithDSA";
    /**
     * Length of DSA signature in bytes.
     */
    public static final int DSA_SIGNATURE_LENGTH_BYTES = 40;

    static {
        try {
            KeyPairGenerator.getInstance(ALGORITHM_DSA);
            Signature.getInstance(ALGORITHM_DSA_SIGNATURE);
        } catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("DSA algorithm is not available.", e);
        }
    }

    private final DSAPrivateKey privateKey;
    private final DSAPublicKey publicKey;

    /**
     * Constructor for creating pair of private and public key.
     *
     * @param privateKey the private key
     * @param publicKey  the corresponding public key
     */
    public DSAKeyPair(final DSAPrivateKey privateKey, final DSAPublicKey publicKey) {
        this.privateKey = requireNonNull(privateKey);
        this.publicKey = requireNonNull(publicKey);
    }

    /**
     * Generate a DSA key pair.
     *
     * @param random SecureRandom instance used for generation.
     * @return Returns the DSA key pair.
     */
    @Nonnull
    public static DSAKeyPair generateDSAKeyPair(final SecureRandom random) {
        // Manually enforce non-null SecureRandom instances. Some libraries/JDKs will default to their own when
        // null is provided. It is preferred to throw NPE such that an issue in the control flow is apparent.
        requireNonNull(random);
        try {
            final KeyPairGenerator kg = KeyPairGenerator.getInstance(ALGORITHM_DSA);
            kg.initialize(DSA_KEY_LENGTH_BITS, random);
            final KeyPair keypair = kg.genKeyPair();
            return new DSAKeyPair((DSAPrivateKey) keypair.getPrivate(), (DSAPublicKey) keypair.getPublic());
        } catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Failed to generate DSA key pair: DSA algorithm is unavailable.", e);
        }
    }

    /**
     * Restore an existing encoded DSA key pair.
     *
     * @param encodedPrivateKey the encoded DSA private key.
     * @param encodedPublicKey  the encoded DSA public key..
     * @return Returns an instance of DSAKeyPair containing the encoded key pair.
     * @throws OtrCryptoException Thrown in case of failure to reconstruct DSA public or private key.
     */
    public static DSAKeyPair restoreDSAKeyPair(final byte[] encodedPrivateKey, final byte[] encodedPublicKey)
            throws OtrCryptoException {
        final PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_DSA);
            final DSAPublicKey publicKey = (DSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            final DSAPrivateKey privateKey = (DSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            return new DSAKeyPair(privateKey, publicKey);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to acquire key factory for DSA algorithm.", e);
        } catch (final InvalidKeySpecException e) {
            throw new OtrCryptoException("Failed to load encoded DSA key pair.", e);
        }
    }

    /**
     * (Re)Create DSA public key based on provided input parameters.
     *
     * @param y y
     * @param p p
     * @param q q
     * @param g g
     * @return Returns DSA public key.
     * @throws OtrCryptoException Throws OtrCryptoException in case of failure to create DSA public key.
     */
    @Nonnull
    public static DSAPublicKey createDSAPublicKey(final BigInteger y, final BigInteger p, final BigInteger q,
            final BigInteger g) throws OtrCryptoException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_DSA);
            final DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
            return (DSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Failed to initialize DSA key factory: DSA algorithm is not supported.", e);
        } catch (final InvalidKeySpecException e) {
            throw new OtrCryptoException("Read invalid public key from input stream.", e);
        }
    }

    /**
     * Get public key from the key pair.
     *
     * @return the public key
     */
    @Nonnull
    public DSAPublicKey getPublic() {
        return this.publicKey;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final DSAKeyPair that = (DSAKeyPair) o;
        return privateKey.equals(that.privateKey) && publicKey.equals(that.publicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKey, publicKey);
    }

    /**
     * Encode the DSA key pair into a byte-array.
     * <p>
     * The public key is encoded using X509 format. The private key is encoded using PKCS8 format.
     *
     * @return Returns an encoded DSA key pair consisting of encoded private and public key.
     */
    @Nonnull
    public EncodedDSAKeyPair encodeDSAKeyPair() {
        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(this.publicKey.getEncoded());
        final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(this.privateKey.getEncoded());
        return new EncodedDSAKeyPair(pkcs8EncodedKeySpec.getEncoded(), x509EncodedKeySpec.getEncoded());
    }

    /**
     * Structure containing encoded DSA key pair.
     */
    public static final class EncodedDSAKeyPair {

        /**
         * PKCS8-encoded private key specification.
         */
        public final byte[] encodedPrivateKey;

        /**
         * X509-encoded public key specification.
         */
        public final byte[] encodedPublicKey;

        private EncodedDSAKeyPair(final byte[] encodedPrivateKey, final byte[] encodedPublicKey) {
            this.encodedPrivateKey = requireNonNull(encodedPrivateKey);
            this.encodedPublicKey = requireNonNull(encodedPublicKey);
        }
    }

    /**
     * Sign bytes with provided private key.
     *
     * @param b          the source content
     * @return Returns signature in bytes.
     */
    @Nonnull
    public byte[] sign(final byte[] b) {
        final BigInteger q = this.privateKey.getParams().getQ();
        final DSASignature signature = signRS(b);
        final int siglen = q.bitLength() / 4;
        assert siglen == DSA_SIGNATURE_LENGTH_BYTES : "BUG: unexpected signature length, are DSA parameters correct?";

        final int rslen = siglen / 2;
        final byte[] rb = asUnsignedByteArray(signature.r);
        final byte[] sb = asUnsignedByteArray(signature.s);

        // Create the final signature array, padded with zeros if necessary.
        final byte[] sig = new byte[siglen];
        System.arraycopy(rb, 0, sig, rslen - rb.length, rb.length);
        System.arraycopy(sb, 0, sig, sig.length - sb.length, sb.length);
        return sig;
    }

    /**
     * Sign data 'b' using DSA private key 'privateKey' and return signature components 'r' and 's'.
     *
     * @param b          The data to be signed.
     * @return Signature components 'r' and 's'.
     */
    @Nonnull
    public DSASignature signRS(final byte[] b) {
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        final Signature signer;
        try {
            signer = Signature.getInstance(ALGORITHM_DSA_SIGNATURE);
            signer.initSign(this.privateKey);
        } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
            // NOTE this should not happen, as we test for availability of algorithms in the static initializer.
            throw new IllegalStateException("BUG: DSA signer initialization failed.", e);
        }
        final DSAParams dsaParams = privateKey.getParams();
        try {
            signer.update(asUnsignedByteArray(20, new BigInteger(1, b).mod(dsaParams.getQ())));
            final BigInteger[] signature = convertSignatureASN1ToP1363(signer.sign());
            return new DSASignature(signature[0], signature[1]);
        } catch (final SignatureException e) {
            throw new IllegalStateException("Failed to produce signature for message.", e);
        } catch (final ProtocolException e) {
            throw new IllegalStateException("BUG: DSA signature algorithm failed to produce valid signature.", e);
        }
    }

    /**
     * Verify DSA signature against expectation using provided DSA public key
     * instance..
     *
     * @param b data expected to be signed.
     * @param pubKey Public key. Provided public key must be an instance of
     * DSAPublicKey.
     * @param rs Components R and S.
     * @throws OtrCryptoException Thrown in case of failed verification.
     */
    public static void verifySignature(final byte[] b, final DSAPublicKey pubKey, final byte[] rs)
            throws OtrCryptoException {
        final int qlen = pubKey.getParams().getQ().bitLength() / 8;
        requireLengthExactly(2 * qlen, rs);
        final ByteBuffer buff = ByteBuffer.wrap(rs);
        final byte[] r = new byte[qlen];
        buff.get(r);
        final byte[] s = new byte[qlen];
        buff.get(s);
        verifySignature(b, pubKey, r, s);
    }

    private static void verifySignature(final byte[] b, final DSAPublicKey pubKey, final byte[] r, final byte[] s)
            throws OtrCryptoException {
        assert !allZeroBytes(r) : "Expected non-zero bytes for r. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(s) : "Expected non-zero bytes for s. This may indicate that a critical bug is present, or it may be a false warning.";
        verifySignature(b, pubKey, new BigInteger(1, r), new BigInteger(1, s));
    }

    /**
     * Verify a message using a signature represented as two MPI components: 'r' and 's'.
     *
     * @param b the message in bytes
     * @param pubKey the DSA public key
     * @param r the signature component 'r'
     * @param s the signature component 's'
     * @throws OtrCryptoException In case of illegal signature.
     */
    public static void verifySignature(final byte[] b, final DSAPublicKey pubKey, final BigInteger r, final BigInteger s)
            throws OtrCryptoException {
        requireNonNull(b);
        assert !allZeroBytes(b) : "Expected non-zero bytes for b. This may indicate that a critical bug is present, or it may be a false warning.";
        final Signature verifier;
        try {
            verifier = Signature.getInstance(ALGORITHM_DSA_SIGNATURE);
            verifier.initVerify(pubKey);
        } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
            throw new OtrCryptoException("DSA verifier initialization failed.", e);
        }
        final DSAParams dsaParams = pubKey.getParams();
        try {
            verifier.update(asUnsignedByteArray(20, new BigInteger(1, b).mod(dsaParams.getQ())));
            verifier.verify(convertSignatureP1363ToASN1(r, s));
        } catch (final SignatureException e) {
            throw new OtrCryptoException("DSA signature validation failed.");
        }
    }

    /**
     * A type representing the DSA signature in its two individual components.
     */
    public static final class DSASignature {

        /**
         * The 'r' component.
         */
        public final BigInteger r;
        /**
         * The 's' component.
         */
        public final BigInteger s;

        /**
         * The DSA signature constructor.
         *
         * @param r the 'r' component
         * @param s the 's' component
         */
        public DSASignature(final BigInteger r, final BigInteger s) {
            this.r = requireNonNull(r);
            this.s = requireNonNull(s);
            assert this.r.bitLength() + this.s.bitLength() <= DSA_SIGNATURE_LENGTH_BYTES * 8
                    : "Expected bit length of 'r' and 's' components to be at most 160 bits (40 bytes).";
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final DSASignature that = (DSASignature) o;
            return Objects.equals(r, that.r) && Objects.equals(s, that.s);
        }

        @Override
        public int hashCode() {
            return Objects.hash(r, s);
        }
    }
}
