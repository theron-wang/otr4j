/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.ValidationException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.DHKeyPair.checkPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.BRACE_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SHARED_SECRET;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SSID;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.THIRD_BRACE_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hwc;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * The OTRv4 Mixed Shared Secret-mechanism.
 */
// REMARK we only compare new `their next` public keys against their previous and our keypair. (So not compared against other past keys.)
public final class MixedSharedSecret implements AutoCloseable {

    private static final int SSID_LENGTH_BYTES = 8;
    private static final int BRACE_KEY_LENGTH_BYTES = 32;
    private static final int K_LENGTH_BYTES = 64;

    /**
     * SecureRandom instance.
     */
    private final SecureRandom random;

    /**
     * Either a hash of the shared DH key: 'KDF_1(0x02 || k_dh, 32)' (every third DH ratchet) or a hash of the previous
     * 'brace_key: KDF_1(0x03 || brace_key, 32)'.
     */
    private final byte[] braceKey = new byte[BRACE_KEY_LENGTH_BYTES];

    /**
     * The Mixed shared secret 'K' is the final shared secret derived from both the brace key and ECDH shared secrets:
     * 'KDF_1(0x04 || K_ecdh || brace_key, 64)'.
     */
    private final byte[] k = new byte[K_LENGTH_BYTES];

    /**
     * Our ECDH key pair.
     */
    @Nonnull
    private final ECDHKeyPair ecdhKeyPair;

    /**
     * The 3072-bit DH shared secret computed from a DH key exchange, serialized as a big-endian unsigned integer.
     */
    @Nonnull
    private final DHKeyPair dhKeyPair;

    /**
     * Other party's ECDH public key.
     */
    @Nonnull
    private final Point theirECDHPublicKey;

    /**
     * Other party's DH public key.
     */
    @Nonnull
    private final BigInteger theirDHPublicKey;

    /**
     * Shared Secret 4.
     *
     * @param random the secure random instance
     * @param ecdhKeyPair our ECDH key pair
     * @param dhKeyPair our DH key pair
     * @param theirNextDH their DH public key
     * @param theirNextECDH their ECDH public key
     */
    public MixedSharedSecret(final SecureRandom random, final ECDHKeyPair ecdhKeyPair, final DHKeyPair dhKeyPair,
            final Point theirNextECDH, final BigInteger theirNextDH) {
        this(random, new byte[BRACE_KEY_LENGTH_BYTES], true, ecdhKeyPair, dhKeyPair, theirNextECDH, theirNextDH);
    }

    /**
     * Shared Secret 4.
     *
     * @param random the secure random instance
     * @param ecdhKeyPair our ECDH key pair
     * @param dhKeyPair our DH key pair
     * @param theirNextDH their DH public key
     * @param theirNextECDH their ECDH public key
     */
    // TODO at call sites, check if their public keys do not correspond to earlier public keys or our own public keys.
    private MixedSharedSecret(final SecureRandom random, final byte[] braceKey, final boolean dhratchet,
            final ECDHKeyPair ecdhKeyPair, final DHKeyPair dhKeyPair, final Point theirNextECDH,
            final BigInteger theirNextDH) {
        this.random = requireNonNull(random);
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        if (!containsPoint(theirNextECDH) || this.ecdhKeyPair.publicKey().constantTimeEquals(theirNextECDH)) {
            throw new IllegalArgumentException("A new, different ECDH public key is expected for initializing the new ratchet.");
        }
        this.theirECDHPublicKey = requireNonNull(theirNextECDH);
        if (!checkPublicKey(theirNextDH) || theirNextDH.equals(this.dhKeyPair.publicKey())) {
            throw new IllegalArgumentException("A new, different DH public key is expected for initializing the new ratchet.");
        }
        this.theirDHPublicKey = requireNonNull(theirNextDH);
        requireLengthExactly(BRACE_KEY_LENGTH_BYTES, braceKey);
        // Calculate new `K` value based on provided ECDH and DH key material, and previous brace key.
        final byte[] k_ecdh;
        try (Point sharedSecret = this.ecdhKeyPair.generateSharedSecret(this.theirECDHPublicKey)) {
            k_ecdh = sharedSecret.encode();
        } catch (final ValidationException e) {
            throw new IllegalStateException("BUG: ECDH public keys should have been verified. No unexpected failures should happen at this point.", e);
        }
        if (dhratchet) {
            final byte[] k_dh = asUnsignedByteArray(this.dhKeyPair.generateSharedSecret(this.theirDHPublicKey));
            kdf(this.braceKey, 0, BRACE_KEY_LENGTH_BYTES, THIRD_BRACE_KEY, k_dh);
            clear(k_dh);
        } else {
            assert !allZeroBytes(braceKey) : "BUG: not performing DH ratchet, but received brace key with all zero-bytes.";
            kdf(this.braceKey, 0, BRACE_KEY_LENGTH_BYTES, BRACE_KEY, braceKey);
        }
        assert !allZeroBytes(this.braceKey) : "BUG: cannot have brace key consisting of all zero-bytes.";
        kdf(this.k, 0, K_LENGTH_BYTES, SHARED_SECRET, k_ecdh, this.braceKey);
        assert !allZeroBytes(this.k) : "BUG: cannot have 'K' consisting of all zero-bytes.";
        clear(k_ecdh);
    }

    /**
     * Close MixedSharedSecret instance by securely clearing used memory that contains sensitive data.
     */
    // FIXME investigate proper closing/clearing procedure given that these instances may be thrown away in case of malicious messages.
    @Override
    public void close() {
        clear(this.braceKey);
        clear(this.k);
        this.ecdhKeyPair.close();
        this.dhKeyPair.close();
    }

    /**
     * Get ephemeral ECDH public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getECDHPublicKey() {
        return this.ecdhKeyPair.publicKey();
    }

    /**
     * Get ephemeral DH public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public BigInteger getDHPublicKey() {
        return this.dhKeyPair.publicKey();
    }

    /**
     * Get "their" (remote) ECDH public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getTheirECDHPublicKey() {
        return this.theirECDHPublicKey;
    }

    /**
     * Get "their" (remote) DH public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public BigInteger getTheirDHPublicKey() {
        return this.theirDHPublicKey;
    }

    /**
     * Get mixed shared secret K.
     *
     * @return Mixed shared secret K.
     */
    @Nonnull
    public byte[] getK() {
        expectNotClosed();
        return this.k.clone();
    }

    /**
     * Generate SSID.
     * <p>
     * NOTE: the only relevant SSID value is the one that is generated from the initial DAKE security parameters.
     * If you call this method at any later time, check if you are sure that you want *this* value or the initial SSID.
     *
     * @return Returns the SSID.
     */
    @Nonnull
    public byte[] generateSSID() {
        expectNotClosed();
        return hwc(SSID_LENGTH_BYTES, SSID, this.k);
    }

    /**
     * Rotate our key pairs in the shared secret.
     *
     * @param dhratchet Indicates whether we need to regenerate the DH key pair as well. (Every third brace key.)
     * @return Returns new instance with our keys rotated.
     */
    @CheckReturnValue
    public MixedSharedSecret rotateOurKeys(final boolean dhratchet) {
        expectNotClosed();
        return new MixedSharedSecret(this.random, this.braceKey, dhratchet, ECDHKeyPair.generate(this.random),
                dhratchet ? DHKeyPair.generate(this.random) : this.dhKeyPair, this.theirECDHPublicKey,
                this.theirDHPublicKey);
    }

    /**
     * Rotate their public keys in the shared secret.
     *
     * @param dhratchet Indicates whether we need to regenerate the DH key pair as well. (Every third brace key.)
     * @param theirNextECDH Their ECDH public key.
     * @param theirNextDH Their DH public key. (Optional. Expected for every third brace key.)
     * @return Returns new instance with their public keys rotated.
     * @throws OtrCryptoException In case of failure to rotate the public keys.
     */
    // FIXME we cannot yet close the keypairs, because we need to forget this instance if the incoming message turns out to be malicious.
    @CheckReturnValue
    public MixedSharedSecret rotateTheirKeys(final boolean dhratchet, final Point theirNextECDH,
            @Nullable final BigInteger theirNextDH) throws OtrCryptoException {
        expectNotClosed();
        if (dhratchet == (theirNextDH == null)) {
            throw new IllegalArgumentException("Their next DH public key is unexpected.");
        }
        if (!containsPoint(theirNextECDH) || this.theirECDHPublicKey.constantTimeEquals(theirNextECDH)
                || this.ecdhKeyPair.publicKey().equals(theirNextECDH)) {
            throw new OtrCryptoException("ECDH public key failed verification.");
        }
        final MixedSharedSecret next;
        if (dhratchet) {
            // This is a DH ratchet. (every third brace key)
            if (!checkPublicKey(theirNextDH) || this.dhKeyPair.publicKey().equals(theirNextDH)
                    || this.theirDHPublicKey.equals(theirNextDH)) {
                throw new OtrCryptoException("DH public key failed verification.");
            }
            next = new MixedSharedSecret(this.random, this.braceKey, true, this.ecdhKeyPair, this.dhKeyPair,
                    theirNextECDH, theirNextDH);
            this.dhKeyPair.close();
        } else {
            // This is NOT a DH ratchet.
            next = new MixedSharedSecret(this.random, this.braceKey, false, this.ecdhKeyPair, this.dhKeyPair,
                    theirNextECDH, this.theirDHPublicKey);
        }
        this.ecdhKeyPair.close();
        return next;
    }

    private void expectNotClosed() {
        if (allZeroBytes(this.braceKey) || allZeroBytes(this.k)) {
            throw new IllegalStateException("Shared secret is already closed/disposed of.");
        }
    }
}
