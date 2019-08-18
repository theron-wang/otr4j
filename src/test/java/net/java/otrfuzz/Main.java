/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otrfuzz;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.messages.DataMessage4;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import static net.java.otr4j.util.SecureRandoms.randomBytes;

public class Main {

    private static final SecureRandom RANDOM = new SecureRandom();

    public static void main(final String[] args) throws IOException {
        final OtrEncodable message = new DataMessage4(Version.FOUR, InstanceTag.random(RANDOM),
                InstanceTag.random(RANDOM), (byte) 0, 0, 0, 0, ECDHKeyPair.generate(RANDOM).getPublicKey(),
                DHKeyPair.generate(RANDOM).getPublicKey(), randomBytes(RANDOM, new byte[80]),
                randomBytes(RANDOM, new byte[64]), new byte[0]);
        final byte[] result = new OtrOutputStream().write(message).toByteArray();
        try (FileOutputStream output = new FileOutputStream("temp", false)) {
            output.write(result);
        }
//        System.err.println(result);
    }
}
