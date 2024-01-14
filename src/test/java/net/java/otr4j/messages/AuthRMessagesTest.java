/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static java.util.Collections.singletonList;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH_R_PHI;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.crypto.ed448.PointTestUtils.createPoint;
import static net.java.otr4j.messages.AuthRMessages.validate;
import static net.java.otr4j.messages.ClientProfilePayload.signClientProfile;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;

@SuppressWarnings("resource")
public final class AuthRMessagesTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testValidateSuccessful() throws ValidationException {
        // Our client profile
        final EdDSAKeyPair bobLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point bobForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair bobDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point bobFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile bobProfile = new ClientProfile(HIGHEST_TAG, bobLongTermKeyPair.getPublicKey(),
                bobForgingKey, singletonList(Version.FOUR), bobDSAKeyPair.getPublic());
        final ClientProfilePayload bobProfilePayload = signClientProfile(bobProfile, Long.MAX_VALUE / 1000,
                bobDSAKeyPair, bobLongTermKeyPair);
        final Point bobY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobB = DHKeyPair.generate(RANDOM).publicKey();
        // Their client profile
        final EdDSAKeyPair aliceLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair aliceDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point aliceFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger aliceFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point aliceForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile aliceProfile = new ClientProfile(SMALLEST_TAG, aliceLongTermKeyPair.getPublicKey(),
                aliceForgingKey, singletonList(Session.Version.FOUR), aliceDSAKeyPair.getPublic());
        final ClientProfilePayload aliceProfilePayload = signClientProfile(aliceProfile, Long.MAX_VALUE / 1000,
                aliceDSAKeyPair, aliceLongTermKeyPair);
        final Point aliceX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger aliceA = DHKeyPair.generate(RANDOM).publicKey();
        // The Auth-I message
        final byte[] phi = MysteriousT4.generatePhi(AUTH_R_PHI, SMALLEST_TAG, HIGHEST_TAG, aliceFirstECDHPublicKey,
                aliceFirstDHPublicKey, bobFirstECDHPublicKey, bobFirstDHPublicKey, "alice@network", "bob@network");
        final byte[] m = MysteriousT4.encode(AUTH_R, bobProfilePayload, aliceProfilePayload, bobY, aliceX,
                bobB, aliceA, phi);
        final Sigma sigma = ringSign(RANDOM, aliceLongTermKeyPair, bobForgingKey, aliceLongTermKeyPair.getPublicKey(),
                bobY, m);
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, aliceProfilePayload, aliceX, aliceA,
                sigma, aliceFirstECDHPublicKey, aliceFirstDHPublicKey);
        AuthRMessages.validate(message, bobProfilePayload, bobProfile, aliceProfile, bobY, bobB, phi);
    }

    @Test(expected = ValidationException.class)
    public void testValidateInstanceTagMismatch() throws ValidationException {
        // Our client profile
        final EdDSAKeyPair bobLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point bobForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair bobDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point bobFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile bobProfile = new ClientProfile(HIGHEST_TAG, bobLongTermKeyPair.getPublicKey(),
                bobForgingKey, singletonList(Version.FOUR), bobDSAKeyPair.getPublic());
        final ClientProfilePayload bobProfilePayload = signClientProfile(bobProfile, Long.MAX_VALUE / 1000,
                bobDSAKeyPair, bobLongTermKeyPair);
        final Point bobY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobB = DHKeyPair.generate(RANDOM).publicKey();
        // Their client profile
        final EdDSAKeyPair aliceLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair aliceDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point aliceFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger aliceFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point aliceForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile aliceProfile = new ClientProfile(new InstanceTag(0x55555555), aliceLongTermKeyPair.getPublicKey(),
                aliceForgingKey, singletonList(Session.Version.FOUR), aliceDSAKeyPair.getPublic());
        final ClientProfilePayload aliceProfilePayload = signClientProfile(aliceProfile, Long.MAX_VALUE / 1000,
                aliceDSAKeyPair, aliceLongTermKeyPair);
        final Point aliceX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger aliceA = DHKeyPair.generate(RANDOM).publicKey();
        // The Auth-I message
        final byte[] phi = MysteriousT4.generatePhi(AUTH_R_PHI, SMALLEST_TAG, HIGHEST_TAG, aliceFirstECDHPublicKey,
                aliceFirstDHPublicKey, bobFirstECDHPublicKey, bobFirstDHPublicKey, "alice@network", "bob@network");
        final byte[] m = MysteriousT4.encode(AUTH_R, bobProfilePayload, aliceProfilePayload, bobY, aliceX,
                bobB, aliceA, phi);
        final Sigma sigma = ringSign(RANDOM, aliceLongTermKeyPair, bobForgingKey, aliceLongTermKeyPair.getPublicKey(),
                bobY, m);
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, aliceProfilePayload, aliceX, aliceA,
                sigma, aliceFirstECDHPublicKey, aliceFirstDHPublicKey);
        AuthRMessages.validate(message, bobProfilePayload, bobProfile, aliceProfile, bobY, bobB, phi);
    }

    // TODO re-create test with illegal ECDH public key
    //@Test(expected = ValidationException.class)
    //public void testValidateIllegalECDHPublicKey() throws ValidationException {
    //    // Define their client
    //    final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
    //    final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
    //    final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
    //    final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
    //            forgingKey, singletonList(Version.FOUR), theirDSAKeyPair.getPublic());
    //    final ClientProfilePayload theirPayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
    //            theirDSAKeyPair, theirLongTermKeyPair);
    //    final Point theirX = createPoint(ONE, ONE);
    //    final BigInteger theirA = DHKeyPair.generate(RANDOM).publicKey();
    //    final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
    //    final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
    //    // Define our client
    //    final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
    //    final Point ourY = ECDHKeyPair.generate(RANDOM).publicKey();
    //    final BigInteger ourB = DHKeyPair.generate(RANDOM).publicKey();
    //    final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
    //    final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
    //    final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
    //    final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
    //    final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
    //            ourForgingKey, singletonList(Session.Version.FOUR), ourDSAKeyPair.getPublic());
    //    final ClientProfilePayload ourPayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
    //            ourDSAKeyPair, ourLongTermKeyPair);
    //    // Define the message to be validated
    //    final byte[] phi = MysteriousT4.generatePhi(AUTH_R_PHI, SMALLEST_TAG, HIGHEST_TAG, theirFirstECDHPublicKey,
    //            theirFirstDHPublicKey, ourFirstECDHPublicKey, ourFirstDHPublicKey, "alice@network",
    //            "bob@network");
    //    final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB, phi);
    //    final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
    //            ourY, m);
    //    final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX, theirA, sigma,
    //            theirFirstECDHPublicKey, theirFirstDHPublicKey);
    //    validate(message, ourPayload, ourProfile, theirProfile, ourY, ourB, phi);
    //}

    @Test(expected = ValidationException.class)
    public void testValidateIllegalDHPublicKey() throws ValidationException {
        // Our client profile
        final EdDSAKeyPair bobLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point bobForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair bobDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point bobFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile bobProfile = new ClientProfile(HIGHEST_TAG, bobLongTermKeyPair.getPublicKey(),
                bobForgingKey, singletonList(Version.FOUR), bobDSAKeyPair.getPublic());
        final ClientProfilePayload bobProfilePayload = signClientProfile(bobProfile, Long.MAX_VALUE / 1000,
                bobDSAKeyPair, bobLongTermKeyPair);
        final Point bobY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobB = DHKeyPair.generate(RANDOM).publicKey();
        // Their client profile
        final EdDSAKeyPair aliceLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair aliceDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point aliceFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger aliceFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point aliceForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile aliceProfile = new ClientProfile(SMALLEST_TAG, aliceLongTermKeyPair.getPublicKey(),
                aliceForgingKey, singletonList(Session.Version.FOUR), aliceDSAKeyPair.getPublic());
        final ClientProfilePayload aliceProfilePayload = signClientProfile(aliceProfile, Long.MAX_VALUE / 1000,
                aliceDSAKeyPair, aliceLongTermKeyPair);
        final Point aliceX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger aliceA = DHKeyPair.generate(RANDOM).publicKey();
        // The Auth-I message
        final byte[] phi = MysteriousT4.generatePhi(AUTH_R_PHI, SMALLEST_TAG, HIGHEST_TAG, aliceFirstECDHPublicKey,
                aliceFirstDHPublicKey, bobFirstECDHPublicKey, bobFirstDHPublicKey, "alice@network", "bob@network");
        final byte[] m = MysteriousT4.encode(AUTH_R, bobProfilePayload, aliceProfilePayload, bobY, aliceX,
                bobB, aliceA, phi);
        final Sigma sigma = ringSign(RANDOM, aliceLongTermKeyPair, bobForgingKey, aliceLongTermKeyPair.getPublicKey(),
                bobY, m);
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, aliceProfilePayload, aliceX, aliceA,
                sigma, aliceFirstECDHPublicKey, aliceFirstDHPublicKey);
        AuthRMessages.validate(message, bobProfilePayload, bobProfile, aliceProfile, bobY, ZERO, phi);
    }

    @Test(expected = ValidationException.class)
    public void testValidateBadMessage() throws ValidationException {
        // Our client profile
        final EdDSAKeyPair bobLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point bobForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair bobDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point bobFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile bobProfile = new ClientProfile(HIGHEST_TAG, bobLongTermKeyPair.getPublicKey(),
                bobForgingKey, singletonList(Version.FOUR), bobDSAKeyPair.getPublic());
        final ClientProfilePayload bobProfilePayload = signClientProfile(bobProfile, Long.MAX_VALUE / 1000,
                bobDSAKeyPair, bobLongTermKeyPair);
        final Point bobY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobB = DHKeyPair.generate(RANDOM).publicKey();
        // Their client profile
        final EdDSAKeyPair aliceLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair aliceDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point aliceFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger aliceFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point aliceForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile aliceProfile = new ClientProfile(SMALLEST_TAG, aliceLongTermKeyPair.getPublicKey(),
                aliceForgingKey, singletonList(Session.Version.FOUR), aliceDSAKeyPair.getPublic());
        final ClientProfilePayload aliceProfilePayload = signClientProfile(aliceProfile, Long.MAX_VALUE / 1000,
                aliceDSAKeyPair, aliceLongTermKeyPair);
        final Point aliceX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger aliceA = DHKeyPair.generate(RANDOM).publicKey();
        // The Auth-I message
        final byte[] phi = MysteriousT4.generatePhi(AUTH_R_PHI, SMALLEST_TAG, HIGHEST_TAG, aliceFirstECDHPublicKey,
                aliceFirstDHPublicKey, bobFirstECDHPublicKey, bobFirstDHPublicKey, "alice@network", "bob@network");
        final byte[] m = MysteriousT4.encode(AUTH_R, bobProfilePayload, aliceProfilePayload, bobY, aliceX,
                bobB, aliceA, phi);
        final Sigma sigma = ringSign(RANDOM, aliceLongTermKeyPair, bobForgingKey, aliceLongTermKeyPair.getPublicKey(),
                bobY, m);
        final AuthRMessage message = new AuthRMessage(ZERO_TAG, HIGHEST_TAG, aliceProfilePayload, aliceX, aliceA,
                sigma, aliceFirstECDHPublicKey, aliceFirstDHPublicKey);
        AuthRMessages.validate(message, bobProfilePayload, bobProfile, aliceProfile, bobY, bobB, phi);
    }
}