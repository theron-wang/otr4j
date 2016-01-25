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

    private static final SecureRandom rand = new SecureRandom();

    @Test
    public void testGeneratedSharedSecretEqual() throws OtrCryptoException {
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(rand);
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(rand);

        assertEquals(OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic()),
                OtrCryptoEngine.generateSecret(bobDHKeyPair.getPrivate(), aliceDHKeyPair.getPublic()));
    }
}
