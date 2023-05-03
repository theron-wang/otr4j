/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import net.java.otr4j.util.Classes;

/**
 * Init uses the static initializer to initialize the parts of cryptography that have run-time dependencies on algorithm
 * support in the Java Runtime Environment. This ensures that all required algorithms are available.
 */
public final class Init {
    static {
        Classes.initialize(OtrCryptoEngine.class, DHKeyPairOTR3.class, DSAKeyPair.class);
    }
}
