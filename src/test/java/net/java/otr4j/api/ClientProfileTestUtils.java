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
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.messages.ClientProfilePayload;

import java.security.SecureRandom;
import java.util.TreeSet;

import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.messages.ClientProfilePayload.signClientProfile;

public final class ClientProfileTestUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair eddsaLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);

    private final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();

    private final DSAKeyPair dsaKeyPair = generateDSAKeyPair();

    private final long expirationTime = System.currentTimeMillis() / 1000 + 86400;

    /**
     * Construct user profile test utils with default parameters.
     */
    public ClientProfileTestUtils() {
    }

    public EdDSAKeyPair getEddsaLongTermKeyPair() {
        return eddsaLongTermKeyPair;
    }

    public ClientProfilePayload createClientProfile() {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, this.eddsaLongTermKeyPair.getPublicKey(),
                this.forgingKey, singleton(Session.Version.FOUR), null);
        return signClientProfile(profile, this.expirationTime, null, this.eddsaLongTermKeyPair);
    }

    public ClientProfilePayload createTransitionalClientProfile() {
        final TreeSet<Integer> versions = new TreeSet<>();
        versions.add(Session.Version.THREE);
        versions.add(Session.Version.FOUR);
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, this.eddsaLongTermKeyPair.getPublicKey(),
                this.forgingKey, versions, this.dsaKeyPair.getPublic());
        return signClientProfile(profile, this.expirationTime, this.dsaKeyPair, this.eddsaLongTermKeyPair);
    }
}
