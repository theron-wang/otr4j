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

import static java.math.BigInteger.ZERO;
import static java.util.Collections.singletonList;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH_I_PHI;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthIMessages.validate;
import static net.java.otr4j.messages.ClientProfilePayload.signClientProfile;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_I;

@SuppressWarnings("resource")
public final class AuthIMessagesTest {

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
        final byte[] phi = MysteriousT4.generatePhi(AUTH_I_PHI, HIGHEST_TAG, SMALLEST_TAG, bobFirstECDHPublicKey,
                bobFirstDHPublicKey, aliceFirstECDHPublicKey, aliceFirstDHPublicKey,
                "bob@network", "alice@network");
        final byte[] m = MysteriousT4.encode(AUTH_I, bobProfilePayload, aliceProfilePayload, bobY, aliceX,
                bobB, aliceA, phi);
        final Sigma sigma = ringSign(RANDOM, bobLongTermKeyPair, bobLongTermKeyPair.getPublicKey(),
                aliceForgingKey, aliceX, m);
        final AuthIMessage message = new AuthIMessage(HIGHEST_TAG, SMALLEST_TAG, sigma);
        validate(message, aliceProfilePayload, aliceProfile, bobProfilePayload, bobProfile, aliceX, bobY, aliceA, bobB,
                phi);
    }

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
        final byte[] phi = MysteriousT4.generatePhi(AUTH_I_PHI, HIGHEST_TAG, SMALLEST_TAG, bobFirstECDHPublicKey,
                bobFirstDHPublicKey, aliceFirstECDHPublicKey, aliceFirstDHPublicKey,
                "bob@network", "alice@network");
        final byte[] m = MysteriousT4.encode(AUTH_I, bobProfilePayload, aliceProfilePayload, bobY, aliceX,
                bobB, aliceA, phi);
        final Sigma sigma = ringSign(RANDOM, bobLongTermKeyPair, bobLongTermKeyPair.getPublicKey(),
                aliceForgingKey, aliceX, m);
        final AuthIMessage message = new AuthIMessage(HIGHEST_TAG, SMALLEST_TAG, sigma);
        validate(message, aliceProfilePayload, aliceProfile, bobProfilePayload, bobProfile, aliceX, bobY, aliceA, ZERO,
                phi);
    }

    @Test(expected = ValidationException.class)
    public void testValidateBadSenderTag() throws ValidationException {
        // Our client profile
        final EdDSAKeyPair bobLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point bobForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair bobDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point bobFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger bobFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile bobProfile = new ClientProfile(new InstanceTag(0x66666666), bobLongTermKeyPair.getPublicKey(),
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
        final byte[] phi = MysteriousT4.generatePhi(AUTH_I_PHI, HIGHEST_TAG, SMALLEST_TAG, bobFirstECDHPublicKey,
                bobFirstDHPublicKey, aliceFirstECDHPublicKey, aliceFirstDHPublicKey,
                "bob@network", "alice@network");
        final byte[] m = MysteriousT4.encode(AUTH_I, bobProfilePayload, aliceProfilePayload, bobY, aliceX,
                bobB, aliceA, phi);
        final Sigma sigma = ringSign(RANDOM, bobLongTermKeyPair, bobLongTermKeyPair.getPublicKey(),
                aliceForgingKey, aliceX, m);
        final AuthIMessage message = new AuthIMessage(HIGHEST_TAG, SMALLEST_TAG, sigma);
        validate(message, aliceProfilePayload, aliceProfile, bobProfilePayload, bobProfile, aliceX, bobY, aliceA, bobB,
                phi);
    }
}