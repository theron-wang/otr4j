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
import java.math.BigInteger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hwc;
import static org.bouncycastle.util.Arrays.concatenate;

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
     * @param purpose                    the purpose for the mysterious 'T' value
     * @param profileAlice               the client profile of Alice
     * @param profileBob                 the client profile of Bob
     * @param x                          the ECDH public key 'X'
     * @param y                          the ECDH public key 'Y'
     * @param a                          the DH public key 'A'
     * @param b                          the DH public key 'B'
     * @param senderFirstECDHPublicKey   the sender's first ECDH public key to use after DAKE completes
     * @param senderFirstDHPublicKey     the sender's first DH public key to use after DAKE completes
     * @param receiverFirstECDHPublicKey the receiver's first ECDH public key to use after DAKE completes
     * @param receiverFirstDHPublicKey   the receiver's first DH public key to use after DAKE completes
     * @param senderTag                  the sender instance tag
     * @param receiverTag                the receiver instance tag
     * @param senderContactID            the sender contact ID
     * @param receiverContactID          the receiver contact ID
     * @return Returns the byte-array representing the mysterious 'T' value based on provided arguments.
     */
    @Nonnull
    public static byte[] encode(final Purpose purpose, final ClientProfilePayload profileAlice,
            final ClientProfilePayload profileBob, final Point x, final Point y, final BigInteger a, final BigInteger b,
            final Point senderFirstECDHPublicKey, final BigInteger senderFirstDHPublicKey,
            final Point receiverFirstECDHPublicKey, final BigInteger receiverFirstDHPublicKey,
            final InstanceTag senderTag, final InstanceTag receiverTag, final String senderContactID,
            final String receiverContactID) {
        final KDFUsage bobsProfileUsage;
        final KDFUsage alicesProfileUsage;
        final KDFUsage phiUsage;
        final byte[] prefix;
        switch (purpose) {
        case AUTH_R:
            bobsProfileUsage = KDFUsage.AUTH_R_BOB_CLIENT_PROFILE;
            alicesProfileUsage = KDFUsage.AUTH_R_ALICE_CLIENT_PROFILE;
            phiUsage = KDFUsage.AUTH_R_PHI;
            prefix = new byte[] {0x00};
            break;
        case AUTH_I:
            bobsProfileUsage = KDFUsage.AUTH_I_BOB_CLIENT_PROFILE;
            alicesProfileUsage = KDFUsage.AUTH_I_ALICE_CLIENT_PROFILE;
            phiUsage = KDFUsage.AUTH_I_PHI;
            prefix = new byte[] {0x01};
            break;
        default:
            throw new UnsupportedOperationException("Unsupported purpose.");
        }
        final byte[] bobsProfileEncoded = hwc(bobsProfileUsage, USER_PROFILE_DERIVATIVE_LENGTH_BYTES,
                OtrEncodables.encode(profileBob));
        final byte[] alicesProfileEncoded = hwc(alicesProfileUsage, USER_PROFILE_DERIVATIVE_LENGTH_BYTES,
                OtrEncodables.encode(profileAlice));
        final byte[] yEncoded = y.encode();
        final byte[] xEncoded = x.encode();
        final byte[] bEncoded = new OtrOutputStream().writeBigInt(b).toByteArray();
        final byte[] aEncoded = new OtrOutputStream().writeBigInt(a).toByteArray();
        final byte[] phi = generatePhi(senderTag, receiverTag, senderFirstECDHPublicKey, senderFirstDHPublicKey,
                receiverFirstECDHPublicKey, receiverFirstDHPublicKey, senderContactID, receiverContactID);
        final byte[] sharedSessionDerivative = hwc(phiUsage, PHI_DERIVATIVE_LENGTH_BYTES, phi);
        return concatenate(new byte[][] {prefix, bobsProfileEncoded, alicesProfileEncoded, yEncoded, xEncoded,
                bEncoded, aEncoded, sharedSessionDerivative});
    }

    /**
     * Generate the shared session state that is used in verification the session consistency. Note that this part is
     * basically only concerned with the correct serialization of provided data.
     * <p>
     * NOTE: the generated phi value is the value defined by the OTRv4 spec, and additional contact ID values which
     * would be part of the implementer contribution.
     *
     * @param senderTag                  The sender instance tag.
     * @param receiverTag                The receiver instance tag.
     * @param senderFirstECDHPublicKey   The sender's first ECDH public key to use after DAKE completes
     * @param senderFirstDHPublicKey     The sender's first DH public key to use after DAKE completes
     * @param receiverFirstECDHPublicKey The receiver's first ECDH public key to use after DAKE completes
     * @param receiverFirstDHPublicKey   The receiver's first DH public key to use after DAKE completes
     * @param senderContactID            The sender's contact ID (i.e. the infrastructure's identifier such as XMPP's
     *                                   bare JID.)
     * @param receiverContactID          The receiver's contact ID (i.e. the infrastructure's identifier such as XMPP's
     *                                   bare JID.)
     * @return Returns generate Phi value.
     */
    @Nonnull
    static byte[] generatePhi(final InstanceTag senderTag, final InstanceTag receiverTag,
            final Point senderFirstECDHPublicKey, final BigInteger senderFirstDHPublicKey,
            final Point receiverFirstECDHPublicKey, final BigInteger receiverFirstDHPublicKey,
            final String senderContactID, final String receiverContactID) {
        final byte[] senderIDBytes = senderContactID.getBytes(UTF_8);
        final byte[] receiverIDBytes = receiverContactID.getBytes(UTF_8);
        return new OtrOutputStream().writeInstanceTag(senderTag).writeInstanceTag(receiverTag)
                .writePoint(senderFirstECDHPublicKey).writeBigInt(senderFirstDHPublicKey)
                .writePoint(receiverFirstECDHPublicKey).writeBigInt(receiverFirstDHPublicKey).writeData(senderIDBytes)
                .writeData(receiverIDBytes).toByteArray();
    }
}
