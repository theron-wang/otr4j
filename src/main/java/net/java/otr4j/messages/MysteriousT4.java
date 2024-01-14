/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrEncodables;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hwc;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;

/**
 * Mysterious value t that is used in phi (shared session state) identification of OTRv4.
 */
public final class MysteriousT4 {

    private static final int USER_PROFILE_DERIVATIVE_LENGTH_BYTES = 64;

    private static final int PHI_DERIVATIVE_LENGTH_BYTES = 64;

    /**
     * Enum to indicate purpose of the mysterious 'T' value. KDF1 derived values are determined by which message type
     * they are intended for.
     */
    public enum Purpose {
        /**
         * Purpose is Auth-R message type.
         */
        AUTH_R,
        /**
         * Purpose is Auth-I message type.
         */
        AUTH_I
    }

    private MysteriousT4() {
        // For now this is a utility class. I'm not sure that this is the final incarnation, however for now, as T is
        // not a full message in itself, it doesn't make sense to implement the AbstractEncodedMessage interface for
        // encoding. For now this will suffice.
    }

    /**
     * Encode provided parameters in an byte-array representation of the mysterious 'T' value.
     *
     * @param purpose the purpose for the mysterious 'T' value
     * @param bobProfile the client profile of Bob
     * @param aliceProfile the client profile of Alice
     * @param bobDakeECDH the DAKE ECDH public key of Bob 
     * @param aliceDakeECDH the DAKE ECDH public key of Alice
     * @param bobDakeDH the DH public key of Bob
     * @param aliceDakeDH the DH public key of Alice
     * @param phi the shared session state (phi)
     * @return Returns the byte-array representing the mysterious 'T' value based on provided arguments.
     */
    @SuppressWarnings({"UnnecessaryDefaultInEnumSwitch", "UnnecessarilyFullyQualified"})
    @Nonnull
    public static byte[] encode(final Purpose purpose, final ClientProfilePayload bobProfile,
            final ClientProfilePayload aliceProfile, final Point bobDakeECDH, final Point aliceDakeECDH,
            final BigInteger bobDakeDH, final BigInteger aliceDakeDH, final byte[] phi) {
        requireLengthExactly(64, phi);
        final KDFUsage bobProfileUsage;
        final KDFUsage aliceProfileUsage;
        final byte prefix;
        switch (purpose) {
        case AUTH_R:
            bobProfileUsage = KDFUsage.AUTH_R_BOB_CLIENT_PROFILE;
            aliceProfileUsage = KDFUsage.AUTH_R_ALICE_CLIENT_PROFILE;
            prefix = 0x00;
            break;
        case AUTH_I:
            bobProfileUsage = KDFUsage.AUTH_I_BOB_CLIENT_PROFILE;
            aliceProfileUsage = KDFUsage.AUTH_I_ALICE_CLIENT_PROFILE;
            prefix = 0x01;
            break;
        default:
            throw new UnsupportedOperationException("Unsupported purpose.");
        }
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            final OtrOutputStream encoder = new OtrOutputStream(buffer);
            final byte[] bobProfileDerivative = hwc(USER_PROFILE_DERIVATIVE_LENGTH_BYTES, bobProfileUsage, OtrEncodables.encode(aliceProfile));
            final byte[] aliceProfileDerivative = hwc(USER_PROFILE_DERIVATIVE_LENGTH_BYTES, aliceProfileUsage, OtrEncodables.encode(bobProfile));
            return encoder.writeByte(prefix)
                    .writeRaw(bobProfileDerivative)
                    .writeRaw(aliceProfileDerivative)
                    .writePoint(bobDakeECDH)
                    .writePoint(aliceDakeECDH)
                    .writeBigInt(bobDakeDH)
                    .writeBigInt(aliceDakeDH)
                    .writeRaw(phi)
                    .toByteArray();
        } catch (final java.io.IOException e) {
            throw new IllegalStateException("BUG: no IOException should occur.", e);
        }
    }

    /**
     * Generate the shared session state that is used in verification the session consistency. Note that this part is
     * basically only concerned with the correct serialization of provided data.
     * <p>
     * NOTE: the generated phi value is the value defined by the OTRv4 spec, and additional contact ID values which
     * would be part of the implementer contribution.
     *
     * @param usage the usage of Phi
     * @param senderTag The sender instance tag.
     * @param receiverTag The receiver instance tag.
     * @param senderECDH0 The sender's first ECDH public key to use after DAKE completes
     * @param senderDH0 The sender's first DH public key to use after DAKE completes
     * @param receiverECDH0 The receiver's first ECDH public key to use after DAKE completes
     * @param receiverDH0 The receiver's first DH public key to use after DAKE completes
     * @param senderContactID The sender's contact ID (i.e. the infrastructure's identifier such as XMPP's
     * bare JID.)
     * @param receiverContactID The receiver's contact ID (i.e. the infrastructure's identifier such as XMPP's
     * bare JID.)
     * @return Returns generate Phi value.
     */
    // TODO this implementation violates OTRv4 spec: spec dictates that we sort values numerically and strings/data lexicographically, then generate Phi from that.
    @Nonnull
    public static byte[] generatePhi(final KDFUsage usage, final InstanceTag senderTag, final InstanceTag receiverTag,
            final Point senderECDH0, final BigInteger senderDH0,
            final Point receiverECDH0, final BigInteger receiverDH0,
            final String senderContactID, final String receiverContactID) {
        final byte[] senderIDBytes = senderContactID.getBytes(UTF_8);
        final byte[] receiverIDBytes = receiverContactID.getBytes(UTF_8);
        return hwc(PHI_DERIVATIVE_LENGTH_BYTES, usage, new OtrOutputStream()
                .writeInstanceTag(senderTag)
                .writeInstanceTag(receiverTag)
                .writePoint(senderECDH0)
                .writeBigInt(senderDH0)
                .writePoint(receiverECDH0)
                .writeBigInt(receiverDH0)
                .writeData(senderIDBytes)
                .writeData(receiverIDBytes)
                .toByteArray());
    }
}
