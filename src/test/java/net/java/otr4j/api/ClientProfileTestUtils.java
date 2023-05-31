/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.messages.ClientProfilePayload;

import java.security.SecureRandom;
import java.util.List;

import static java.util.Collections.singletonList;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.messages.ClientProfilePayload.signClientProfile;

public final class ClientProfileTestUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);

    private final EdDSAKeyPair forgingKeyPair = EdDSAKeyPair.generate(RANDOM);

    private final DSAKeyPair dsaKeyPair = generateDSAKeyPair(RANDOM);

    private final long expirationTime = System.currentTimeMillis() / 1000 + 86400;

    /**
     * Construct user profile test utils with default parameters.
     */
    public ClientProfileTestUtils() {
    }

    public EdDSAKeyPair getLongTermKeyPair() {
        return this.longTermKeyPair;
    }

    public EdDSAKeyPair getForgingKeyPair() {
        return this.forgingKeyPair;
    }
    
    public DSAKeyPair getLegacyKeyPair() {
        return this.dsaKeyPair;
    }

    public ClientProfilePayload createClientProfile() {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(),
                this.forgingKeyPair.getPublicKey(), singletonList(Session.Version.FOUR), null);
        return signClientProfile(profile, this.expirationTime, null, this.longTermKeyPair);
    }

    public ClientProfilePayload createTransitionalClientProfile() {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(),
                this.forgingKeyPair.getPublicKey(), List.of(Session.Version.THREE, Session.Version.FOUR),
                this.dsaKeyPair.getPublic());
        return signClientProfile(profile, this.expirationTime, this.dsaKeyPair, this.longTermKeyPair);
    }
}
