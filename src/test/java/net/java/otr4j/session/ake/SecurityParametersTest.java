package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.crypto.SharedSecretTestUtil;
import org.junit.Test;
import static org.mockito.Mockito.mock;

public class SecurityParametersTest {
    
    private static final SecureRandom RANDOM = new SecureRandom();

    public SecurityParametersTest() {
    }

    @Test
    public void testConstruction() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final KeyPair localDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final KeyPair remoteDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(3, localDHKeyPair, remoteLongTermPublicKey, (DHPublicKey) remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalVersion() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final KeyPair localDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final KeyPair remoteDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(1, localDHKeyPair, remoteLongTermPublicKey, (DHPublicKey) remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionNegativeVersion() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final KeyPair localDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final KeyPair remoteDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(-1, localDHKeyPair, remoteLongTermPublicKey, (DHPublicKey) remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullLocalDHKeyPair() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final KeyPair remoteDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(3, null, remoteLongTermPublicKey, (DHPublicKey) remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullRemoteLongTermPublicKey() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final KeyPair localDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final KeyPair remoteDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        new SecurityParameters(3, localDHKeyPair, null, (DHPublicKey) remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullRemoteDHPublicKey() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final KeyPair localDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(3, localDHKeyPair, remoteLongTermPublicKey, null, s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullSharedSecret() {
        final KeyPair localDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        final KeyPair remoteDHKeyPair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        new SecurityParameters(3, localDHKeyPair, remoteLongTermPublicKey, (DHPublicKey) remoteDHKeyPair.getPublic(), null);
    }
}
