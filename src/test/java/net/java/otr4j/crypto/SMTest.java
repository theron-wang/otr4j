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
import net.java.otr4j.crypto.SM.SMException;
import net.java.otr4j.io.OtrOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import org.junit.Test;

/**
 * Tests for Socialist Millionaire Protocol.
 *
 * @author Danny van Heumen
 */
public class SMTest {
    
    private final SecureRandom sr = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @SuppressWarnings({"ThrowableInstanceNotThrown", "ThrowableInstanceNeverThrown", "ResultOfObjectAllocationIgnored"})
    public void testConstructSMException() {
        new SM.SMException();
    }

    @Test
    public void testConstructSMExceptionMessage() {
        final SM.SMException e = new SM.SMException("Hello world!");
        assertEquals("Hello world!", e.getMessage());
    }

    @Test
    public void testConstructSMExceptionThrowable() {
        @SuppressWarnings({"ThrowableInstanceNotThrown", "ThrowableInstanceNeverThrown"})
        final Throwable t = new Throwable("bad stuff happened");
        final SM.SMException e = new SM.SMException(t);
        assertSame(t, e.getCause());
    }

    @Test
    public void testConstructSMExceptionMessageThrowable() {
        @SuppressWarnings({"ThrowableInstanceNotThrown", "ThrowableInstanceNeverThrown"})
        final Throwable t = new Throwable("bad stuff happened");
        final SM.SMException e = new SM.SMException("Hello world!", t);
        assertEquals("Hello world!", e.getMessage());
        assertSame(t, e.getCause());
    }

    @Test
    @SuppressWarnings({"ThrowableInstanceNotThrown", "ThrowableInstanceNeverThrown", "ResultOfObjectAllocationIgnored"})
    public void testAbortedException() {
        new SM.SMAbortedException("Stuff was aborted!");
    }

    @Test
    public void testCheckGroupElemValid() throws SM.SMException {
        State.checkGroupElem(BigInteger.TEN);
    }

    @Test
    public void testCheckGroupElemJustValidLowerBound() throws SM.SMException {
        State.checkGroupElem(BigInteger.valueOf(2l));
    }

    @Test(expected = SM.SMException.class)
    public void testCheckGroupElemTooSmall() throws SM.SMException {
        State.checkGroupElem(BigInteger.ONE);
    }

    @Test
    public void testCheckGroupElemJustValidUpperBound() throws SM.SMException {
        State.checkGroupElem(SM.MODULUS_MINUS_2);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckGroupElemTooLarge() throws SM.SMException {
        State.checkGroupElem(SM.MODULUS_MINUS_2.add(BigInteger.ONE));
    }

    @Test
    public void testCheckExponValid() throws SM.SMException {
        State.checkExpon(BigInteger.TEN);
    }

    @Test
    public void testCheckExponJustValidLowerBound() throws SM.SMException {
        State.checkExpon(BigInteger.ONE);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckExponTooSmall() throws SM.SMException {
        State.checkExpon(BigInteger.ZERO);
    }

    @Test
    public void testCheckExponJustValidUpperBound() throws SM.SMException {
        State.checkExpon(SM.ORDER_S.subtract(BigInteger.ONE));
    }

    @Test(expected = SM.SMException.class)
    public void testCheckExponTooLarge() throws SM.SMException {
        State.checkExpon(SM.ORDER_S);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckKnowLog() throws SM.SMException {
        final State sm = new State(sr) {
            @Override
            SM.Status status() {
                return SM.Status.UNDECIDED;
            }
        };
        sm.checkKnowLog(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, 0);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckEqualCoords() throws SM.SMException {
        final State sm = new State(sr) {
            @Override
            SM.Status status() {
                return SM.Status.UNDECIDED;
            }
        };
        sm.checkEqualCoords(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(100L), BigInteger.valueOf(50L), BigInteger.valueOf(25L), BigInteger.valueOf(12L), 0);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckEqualLogs() throws SM.SMException {
        final State sm = new State(sr) {
            @Override
            SM.Status status() {
                return SM.Status.UNDECIDED;
            }
        };
        sm.checkEqualLogs(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(23L), BigInteger.valueOf(35L), 0);
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
        new SM(sr);
    }

    @Test
    public void testSuccessfulSMPConversation() throws SM.SMException, OtrCryptoException, Exception {

        // Alice
        final SM alice = new SM(sr);
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());

        // Bob
        final SM bob = new SM(sr);
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Shared secret
        final byte[] secret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final BigInteger s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytes = combinedSecret(alicePublic, bobPublic, s, secret);

        // SMP session execution
        assertEquals(SM.Status.UNDECIDED, alice.status());
        assertEquals(SM.Status.UNDECIDED, bob.status());

        final byte[] msg1 = alice.step1(combinedSecretBytes);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.UNDECIDED, bob.status());

        bob.step2a(msg1);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.INPROGRESS, bob.status());

        final byte[] msg2 = bob.step2b(combinedSecretBytes);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.INPROGRESS, bob.status());

        final byte[] msg3 = alice.step3(msg2);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.INPROGRESS, bob.status());

        final byte[] msg4 = bob.step4(msg3);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.SUCCEEDED, bob.status());

        alice.step5(msg4);
        // Evaluate session end result
        assertEquals(SM.Status.SUCCEEDED, alice.status());
        assertEquals(SM.Status.SUCCEEDED, bob.status());
    }

    @Test
    public void testUnsuccessfulSMPConversationBadSecret() throws SM.SMException, OtrCryptoException, Exception {

        // Alice
        final SM alice = new SM(sr);
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());

        // Bob
        final SM bob = new SM(sr);
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Shared secret
        final byte[] aliceSecret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final byte[] bobSecret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 't' };
        final BigInteger s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytesAlice = combinedSecret(alicePublic, bobPublic, s, aliceSecret);
        final byte[] combinedSecretBytesBob = combinedSecret(alicePublic, bobPublic, s, bobSecret);

        // SMP session execution
        assertEquals(SM.Status.UNDECIDED, alice.status());
        assertEquals(SM.Status.UNDECIDED, bob.status());

        final byte[] msg1 = alice.step1(combinedSecretBytesAlice);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.UNDECIDED, bob.status());

        bob.step2a(msg1);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.INPROGRESS, bob.status());

        final byte[] msg2 = bob.step2b(combinedSecretBytesBob);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.INPROGRESS, bob.status());

        final byte[] msg3 = alice.step3(msg2);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.INPROGRESS, bob.status());

        final byte[] msg4 = bob.step4(msg3);
        assertEquals(SM.Status.INPROGRESS, alice.status());
        assertEquals(SM.Status.FAILED, bob.status());

        alice.step5(msg4);
        // Evaluate session end result
        assertEquals(SM.Status.FAILED, alice.status());
        assertEquals(SM.Status.FAILED, bob.status());
    }

    @Test
    public void testVerifyCorrectSpecifiedStatusStateExpect1() {
        assertEquals(SM.Status.FAILED, new StateExpect1(sr, SM.Status.FAILED).status());
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect1CorrectlyAbortOnAnswerBeforeQuestion() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.step2b(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect1CorrectlyAbortOnMessage2() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.step3(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect1CorrectlyAbortOnMessage3() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.step4(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect1CorrectlyAbortOnMessage4() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.step5(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnInit() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step1(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnMessage1() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step2a(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnMessage1Continuation() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step2b(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnMessage3() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step4(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnMessage4() throws SM.SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step5(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect3CorrectlyAbortOnInit() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        final SM sm = prepareStateExpect3();
        sm.step1(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect3CorrectlyAbortOnMessage1() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        final SM sm = prepareStateExpect3();
        sm.step2a(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect3CorrectlyAbortOnMessage1Continuation() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        final SM sm = prepareStateExpect3();
        sm.step2b(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect3CorrectlyAbortOnMessage4() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        final SM sm = prepareStateExpect3();
        sm.step5(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnInit() throws NoSuchProviderException, OtrCryptoException, SM.SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step1(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnMessage1() throws NoSuchProviderException, OtrCryptoException, SM.SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step2a(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnMessage1Continuation() throws NoSuchProviderException, OtrCryptoException, SM.SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step2b(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnMessage2() throws NoSuchProviderException, OtrCryptoException, SM.SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step3(new byte[0]);
    }

    @Test(expected = SM.SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnMessage3() throws NoSuchProviderException, OtrCryptoException, SM.SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step4(new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateWithNullSecureRandom() {
        new State(null) {
            @Override
            SM.Status status() {
                return SM.Status.UNDECIDED;
            }
        };
    }

    @Test
    public void testSMStep2aWithSMException() throws SM.SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final State s = new State(sr) {

            @Override
            void smpMessage1a(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.UNDECIDED;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step2a(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep2aWithRuntimeException() throws SM.SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final State s = new State(sr) {

            @Override
            void smpMessage1a(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.UNDECIDED;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step2a(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep2bWithSMException() throws SM.SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final State s = new State(sr) {

            @Override
            byte[] smpMessage1b(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step2b(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep2bWithRuntimeException() throws SM.SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final State s = new State(sr) {

            @Override
            byte[] smpMessage1b(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step2b(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep3WithSMException() throws SM.SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final State s = new State(sr) {

            @Override
            byte[] smpMessage2(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step3(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep3WithRuntimeException() throws SM.SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final State s = new State(sr) {

            @Override
            byte[] smpMessage2(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step3(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep4WithSMException() throws SM.SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final State s = new State(sr) {

            @Override
            byte[] smpMessage3(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step4(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep4WithRuntimeException() throws SM.SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final State s = new State(sr) {

            @Override
            byte[] smpMessage3(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step4(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep5WithSMException() throws SM.SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final State s = new State(sr) {

            @Override
            void smpMessage4(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step5(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    @Test
    public void testSMStep5WithRuntimeException() throws SM.SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final State s = new State(sr) {

            @Override
            void smpMessage4(SM bstate, byte[] input) throws SM.SMAbortedException, SMException {
                throw e;
            }

            @Override
            SM.Status status() {
                return SM.Status.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step5(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SM.Status.CHEATED, sm.status());
    }

    private SM prepareStateExpect4() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        // Alice
        final SM alice = new SM(sr);
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());
        // Bob
        final SM bob = new SM(sr);
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Prepare sm instance for StateExpect3.
        final byte[] secret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final BigInteger s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytes = combinedSecret(alicePublic, bobPublic, s, secret);
        final byte[] msg1 = alice.step1(combinedSecretBytes);
        bob.step2a(msg1);
        final byte[] msg2 = bob.step2b(combinedSecretBytes);
        alice.step3(msg2);
        return alice;
    }

    private SM prepareStateExpect3() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        // Alice
        final SM alice = new SM(sr);
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());
        // Bob
        final SM bob = new SM(sr);
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Prepare sm instance for StateExpect3.
        final byte[] secret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final BigInteger s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytes = combinedSecret(alicePublic, bobPublic, s, secret);
        final byte[] msg1 = alice.step1(combinedSecretBytes);
        bob.step2a(msg1);
        bob.step2b(combinedSecretBytes);
        return bob;
    }

    private byte[] combinedSecret(final byte[] alicePublic, final byte[] bobPublic, final BigInteger s, final byte[] secret) throws Exception {
        final byte[] sessionBytes = computeSessionId(s);
        final byte[] combinedSecret = new byte[1 + alicePublic.length + bobPublic.length + sessionBytes.length + secret.length];
        combinedSecret[0] = 1;
        System.arraycopy(alicePublic, 0, combinedSecret, 1, alicePublic.length);
        System.arraycopy(bobPublic, 0, combinedSecret, 1+alicePublic.length, bobPublic.length);
        System.arraycopy(sessionBytes, 0, combinedSecret, 1+alicePublic.length+bobPublic.length, sessionBytes.length);
        System.arraycopy(secret, 0, combinedSecret, 1+alicePublic.length+bobPublic.length+sessionBytes.length, secret.length);
        return MessageDigest.getInstance("SHA-256").digest(combinedSecret);
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
