/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import com.google.errorprone.annotations.MustBeClosed;

import javax.annotation.Nonnull;

import static net.java.otr4j.crypto.OtrCryptoEngine4.AUTHENTICATOR_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.EXTRA_SYMMETRIC_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTHENTICATOR;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.EXTRA_SYMMETRIC_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.MAC_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.MESSAGE_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.MK_ENC_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.MK_MAC_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hcmac;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.Arrays.clear;

/**
 * Encrypt/decrypt and authenticate/verify using the secret key material in the MessageKeys.
 * <p>
 * NOTE: Please ensure that message keys are appropriately cleared by calling {@link #close()} after use.
 */
// TODO make immutable, closed == allZeroBytes(this.encrypt)?
public final class MessageKeys implements AutoCloseable {

    /**
     * Flag to indicate when MessageKeys instanced has been cleaned up.
     */
    private boolean closed = false;

    /**
     * Encryption/Decryption key. (MUST be cleared after use.)
     */
    private final byte[] encrypt;

    /**
     * Extra Symmetric Key. (MUST be cleared after use.)
     */
    private final byte[] extraSymmetricKey;

    /**
     * Generate MessageKeys from provided chainkey.
     *
     * @param chainkey the chainkey
     * @return returns MessageKeys corresponding to provided chainkey
     */
    @MustBeClosed
    @Nonnull
    public static MessageKeys fromChainkey(final byte[] chainkey) {
        // FIXME consider making this a run-time check, because we use a dummy with all-zeroes value. So that way we also detect programming errors. (See `testEncryptionAfterRotation`)
        assert !allZeroBytes(chainkey) : "Expected chainkey of random data instead of all zero-bytes.";
        final byte[] encrypt = kdf(MK_ENC_LENGTH_BYTES, MESSAGE_KEY, chainkey);
        final byte[] extraSymmetricKey = kdf(EXTRA_SYMMETRIC_KEY_LENGTH_BYTES, EXTRA_SYMMETRIC_KEY,
                new byte[]{(byte) 0xff}, chainkey);
        return new MessageKeys(encrypt, extraSymmetricKey);
    }

    /**
     * Construct Keys instance.
     *
     * @param encrypt message key for encryption
     * @param extraSymmetricKey extra symmetric key
     */
    @MustBeClosed
    private MessageKeys(final byte[] encrypt, final byte[] extraSymmetricKey) {
        assert !allZeroBytes(encrypt) : "Expected encryption key of \"random\" data, instead of all zero-bytes.";
        this.encrypt = requireLengthExactly(MK_ENC_LENGTH_BYTES, encrypt);
        assert !allZeroBytes(extraSymmetricKey) : "Expected extra symmetric key of \"random\" data, instead of all zero-bytes.";
        this.extraSymmetricKey = requireLengthExactly(EXTRA_SYMMETRIC_KEY_LENGTH_BYTES, extraSymmetricKey);
    }

    /**
     * Copy an instance of MessageKeys that can be independently handled and cloned.
     *
     * @return returns a copy of the instance
     */
    @MustBeClosed
    @Nonnull
    public MessageKeys copy() {
        requireNotClosed();
        return new MessageKeys(this.encrypt.clone(), this.extraSymmetricKey.clone());
    }

    /**
     * Clear sensitive material.
     */
    @Override
    public void close() {
        clear(this.encrypt);
        clear(this.extraSymmetricKey);
        this.closed = true;
    }

    /**
     * Encrypt a message using a random nonce.
     *
     * @param message The plaintext message.
     * @return Returns a result containing the ciphertext and nonce used.
     */
    @Nonnull
    public byte[] encrypt(final byte[] message) {
        requireNotClosed();
        return OtrCryptoEngine4.encrypt(this.encrypt, message);
    }

    /**
     * Decrypt a ciphertext.
     *
     * @param ciphertext The ciphertext.
     * @return Returns the plaintext message.
     */
    @Nonnull
    public byte[] decrypt(final byte[] ciphertext) {
        requireNotClosed();
        return OtrCryptoEngine4.decrypt(this.encrypt, ciphertext);
    }

    /**
     * Get the authenticator (MAC).
     * <p>
     * This method only performs the final hash calculation that includes the MAC key. The internal hash calculation
     * defined by OTRv4 is expected to be performed prior to calling this method:
     * <pre>
     *       Authenticator = KDF_1(usageAuthenticator || MKmac || data_message_sections, 64)
     * </pre>
     *
     * @param dataMessageSections The data message sections (excluding Authenticator and Revealed MACs).
     * @return Returns the MAC. (Must be cleared separately.)
     */
    @Nonnull
    public byte[] authenticate(final byte[] dataMessageSections) {
        requireNotClosed();
        final byte[] mac = kdf(MK_MAC_LENGTH_BYTES, MAC_KEY, this.encrypt);
        final byte[] authenticator = hcmac(AUTHENTICATOR, AUTHENTICATOR_LENGTH_BYTES, mac, dataMessageSections);
        clear(mac);
        assert !allZeroBytes(authenticator) : "Expected non-zero bytes in authenticator";
        return authenticator;
    }

    /**
     * Verify a given authenticator against the expected authentication hash.
     *
     * @param dataMessageSection The data message section content to be authenticated.
     * @param authenticator The authenticator value.
     * @throws OtrCryptoException In case of failure to verify the authenticator against the data message section
     * content.
     */
    public void verify(final byte[] dataMessageSection, final byte[] authenticator) throws OtrCryptoException {
        assert !allZeroBytes(authenticator) : "Expected non-zero bytes in authenticator";
        requireNotClosed();
        final byte[] expectedAuthenticator = authenticate(dataMessageSection);
        final boolean failure = !constantTimeEquals(expectedAuthenticator, authenticator);
        clear(expectedAuthenticator);
        if (failure) {
            throw new OtrCryptoException("The authenticator is invalid.");
        }
    }

    /**
     * Get the Extra Symmetric Key.
     *
     * @return Returns the Extra Symmetric Key. (Instance must be cleared by user.)
     */
    @Nonnull
    public byte[] getExtraSymmetricKey() {
        requireNotClosed();
        return this.extraSymmetricKey.clone();
    }

    private void requireNotClosed() {
        if (this.closed) {
            throw new IllegalStateException("BUG: Use of closed MessageKeys instance.");
        }
    }
}
