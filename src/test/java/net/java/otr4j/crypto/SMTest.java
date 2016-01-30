package net.java.otr4j.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import net.java.otr4j.io.OtrOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

/**
 * Tests for Socialist Millionaire Protocol.
 *
 * @author Danny van Heumen
 */
public class SMTest {
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testCheckGroupElemValid() throws SM.SMException {
        SM.checkGroupElem(BigInteger.TEN);
    }

    @Test
    public void testCheckGroupElemJustValidLowerBound() throws SM.SMException {
        SM.checkGroupElem(BigInteger.valueOf(2l));
    }

    @Test(expected = SM.SMException.class)
    public void testCheckGroupElemTooSmall() throws SM.SMException {
        SM.checkGroupElem(BigInteger.ONE);
    }

    @Test
    public void testCheckGroupElemJustValidUpperBound() throws SM.SMException {
        SM.checkGroupElem(SM.MODULUS_MINUS_2);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckGroupElemTooLarge() throws SM.SMException {
        SM.checkGroupElem(SM.MODULUS_MINUS_2.add(BigInteger.ONE));
    }

    @Test
    public void testCheckExponValid() throws SM.SMException {
        SM.checkExpon(BigInteger.TEN);
    }

    @Test
    public void testCheckExponJustValidLowerBound() throws SM.SMException {
        SM.checkExpon(BigInteger.ONE);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckExponTooSmall() throws SM.SMException {
        SM.checkExpon(BigInteger.ZERO);
    }

    @Test
    public void testCheckExponJustValidUpperBound() throws SM.SMException {
        SM.checkExpon(SM.ORDER_S.subtract(BigInteger.ONE));
    }

    @Test(expected = SM.SMException.class)
    public void testCheckExponTooLarge() throws SM.SMException {
        SM.checkExpon(SM.ORDER_S);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckKnowLog() throws SM.SMException {
        SM.checkKnowLog(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(100L), 0);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckEqualCoords() throws SM.SMException {
        final SM.SMState state = new SM.SMState();
        state.g1 = state.g2 = state.g3 = BigInteger.ONE;
        SM.checkEqualCoords(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(100L), BigInteger.valueOf(50L), state, 0);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckEqualLogs() throws SM.SMException {
        final SM.SMState state = new SM.SMState();
        state.g1 = state.g3o = state.qab = BigInteger.ONE;
        SM.checkEqualLogs(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, state, 0);
    }

    @Test
    public void testUnserializeSerializedBigIntArray() throws SM.SMException {
        final BigInteger[] target = new BigInteger[] {
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.valueOf(125L),
            BigInteger.valueOf(2500000L),
        };
        assertArrayEquals(target, SM.unserialize(SM.serialize(target)));
    }

    @Test
    public void testUnserializeZeroLength() throws SM.SMException {
        final byte[] data = new byte[] { 0, 0, 0, 0 };
        final BigInteger[] result = SM.unserialize(data);
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test(expected = SM.SMException.class)
    public void testUnserializeLargeSignedLength() throws SM.SMException {
        final byte[] data = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
        SM.unserialize(data);
    }

    @Test(expected = NullPointerException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructionNullSecureRandom() {
        new SM(null);
    }

    @Test
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructionWithValidSecureRandom() {
        new SM(new SecureRandom());
    }

    @Test
    public void testSuccessfulSMPConversation() throws SM.SMException, OtrCryptoException, Exception {
        final SecureRandom rand = new SecureRandom();

        // Alice
        final SM.SMState alice = new SM.SMState();
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(rand);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());

        // Bob
        final SM.SMState bob = new SM.SMState();
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(rand);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Shared secret
        final byte[] secret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final BigInteger s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytes = combinedSecret(alicePublic, bobPublic, s, secret);

        // SMP session execution
        final SM sm = new SM(rand);
        assertEquals(SM.PROG_OK, alice.smProgState);
        assertEquals(SM.PROG_OK, bob.smProgState);

        final byte[] msg1 = sm.step1(alice, combinedSecretBytes);
        assertEquals(SM.PROG_OK, alice.smProgState);
        assertEquals(SM.PROG_OK, bob.smProgState);

        sm.step2a(bob, msg1);
        assertEquals(SM.PROG_OK, alice.smProgState);
        assertEquals(SM.PROG_OK, bob.smProgState);

        final byte[] msg2 = sm.step2b(bob, combinedSecretBytes);
        assertEquals(SM.PROG_OK, alice.smProgState);
        assertEquals(SM.PROG_OK, bob.smProgState);

        final byte[] msg3 = sm.step3(alice, msg2);
        assertEquals(SM.PROG_OK, alice.smProgState);
        assertEquals(SM.PROG_OK, bob.smProgState);

        final byte[] msg4 = sm.step4(bob, msg3);
        assertEquals(SM.PROG_OK, alice.smProgState);
        assertEquals(SM.PROG_SUCCEEDED, bob.smProgState);

        sm.step5(alice, msg4);
        // Evaluate session end result
        assertEquals(SM.PROG_SUCCEEDED, alice.smProgState);
        assertEquals(SM.PROG_SUCCEEDED, bob.smProgState);
    }

    private byte[] combinedSecret(final byte[] alicePublic, final byte[] bobPublic, final BigInteger s, final byte[] secret) throws Exception {
        final byte[] sessionBytes = computeSessionId(s);
        final byte[] combinedSecret = new byte[1 + alicePublic.length + bobPublic.length + sessionBytes.length + secret.length];
        combinedSecret[0] = 1;
        System.arraycopy(alicePublic, 0, combinedSecret, 1, alicePublic.length);
        System.arraycopy(bobPublic, 0, combinedSecret, 1+alicePublic.length, bobPublic.length);
        System.arraycopy(sessionBytes, 0, combinedSecret, 1+alicePublic.length+bobPublic.length, sessionBytes.length);
        System.arraycopy(secret, 0, combinedSecret, 1+alicePublic.length+bobPublic.length+sessionBytes.length, secret.length);
        return combinedSecret;
    }

	/* Compute secret session ID as hash of agreed secret */
	private static byte[] computeSessionId(final BigInteger s) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final OtrOutputStream oos = new OtrOutputStream(out);
        oos.write(0x00);
        oos.writeBigInt(s);
        final byte[] sdata = out.toByteArray();
        oos.close();

		/* Calculate the session id */
		final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		final byte[] res = sha256.digest(sdata);
		final byte[] secure_session_id = new byte[8];
		System.arraycopy(res, 0, secure_session_id, 0, 8);
		return secure_session_id;
	}

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA", "BC");
        return kg.genKeyPair();
    }
}
