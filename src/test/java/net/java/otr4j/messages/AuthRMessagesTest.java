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
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                forgingKey, singletonList(Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final ECDHKeyPair theirX = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair theirA = DHKeyPair.generate(RANDOM);
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final ECDHKeyPair ourY = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair ourB = DHKeyPair.generate(RANDOM);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Session.Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX.publicKey(), ourY.publicKey(),
                theirA.publicKey(), ourB.publicKey(), theirFirstECDHPublicKey, theirFirstDHPublicKey,
                ourFirstECDHPublicKey, ourFirstDHPublicKey, SMALLEST_TAG, HIGHEST_TAG, "alice@network",
                "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY.publicKey(), m);
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX.publicKey(),
                theirA.publicKey(), sigma, theirFirstECDHPublicKey, theirFirstDHPublicKey);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY.publicKey(), ourB.publicKey(), ourFirstECDHPublicKey, ourFirstDHPublicKey);
    }

    @Test(expected = ValidationException.class)
    public void testValidateInstanceTagMismatch() throws ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(new InstanceTag(257), theirLongTermKeyPair.getPublicKey(),
                forgingKey, singletonList(Session.Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirA = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).publicKey();
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Session.Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB,
                theirFirstECDHPublicKey, theirFirstDHPublicKey, ourFirstECDHPublicKey, ourFirstDHPublicKey,
                SMALLEST_TAG, HIGHEST_TAG, "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY, m);
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX, theirA, sigma,
                theirFirstECDHPublicKey, theirFirstDHPublicKey);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY, ourB, ourFirstECDHPublicKey, ourFirstDHPublicKey);
    }

    @Test(expected = ValidationException.class)
    public void testValidateIllegalECDHPublicKey() throws ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                forgingKey, singletonList(Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirX = createPoint(ONE, ONE);
        final BigInteger theirA = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).publicKey();
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Session.Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB,
                theirFirstECDHPublicKey, theirFirstDHPublicKey, ourFirstECDHPublicKey, ourFirstDHPublicKey,
                SMALLEST_TAG, HIGHEST_TAG, "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY, m);
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX, theirA, sigma,
                theirFirstECDHPublicKey, theirFirstDHPublicKey);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY, ourB, ourFirstECDHPublicKey, ourFirstDHPublicKey);
    }

    @Test(expected = ValidationException.class)
    public void testValidateIllegalDHPublicKey() throws ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                forgingKey, singletonList(Session.Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirA = ZERO;
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).publicKey();
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Session.Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB,
                theirFirstECDHPublicKey, theirFirstDHPublicKey, ourFirstECDHPublicKey, ourFirstDHPublicKey,
                SMALLEST_TAG, HIGHEST_TAG, "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY, m);
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX, theirA, sigma,
                theirFirstECDHPublicKey, theirFirstDHPublicKey);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY, ourB, ourFirstECDHPublicKey, ourFirstDHPublicKey);
    }

    @Test(expected = ValidationException.class)
    public void testValidateBadMessage() throws ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                forgingKey, singletonList(Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirA = ZERO;
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).publicKey();
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Session.Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB,
                theirFirstECDHPublicKey, theirFirstDHPublicKey, ourFirstECDHPublicKey, ourFirstDHPublicKey,
                SMALLEST_TAG, HIGHEST_TAG, "", "");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY, m);
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX, theirA, sigma,
                theirFirstECDHPublicKey, theirFirstDHPublicKey);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY, ourB, ourFirstECDHPublicKey, ourFirstDHPublicKey);
    }
}