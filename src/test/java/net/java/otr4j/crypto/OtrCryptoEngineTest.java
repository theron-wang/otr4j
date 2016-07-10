/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import java.security.KeyPair;
import java.security.SecureRandom;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for OtrCryptoEngine.
 *
 * @author Danny van Heumen
 */
public class OtrCryptoEngineTest {

    private static final SecureRandom RAND = new SecureRandom();

    @Test
    public void testGeneratedSharedSecretEqual() throws OtrCryptoException {
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RAND);
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RAND);

        assertEquals(OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic()),
                OtrCryptoEngine.generateSecret(bobDHKeyPair.getPrivate(), aliceDHKeyPair.getPublic()));
    }
}
