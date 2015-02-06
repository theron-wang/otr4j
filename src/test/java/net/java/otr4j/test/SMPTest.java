
package net.java.otr4j.test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import net.java.otr4j.OtrException;
import net.java.otr4j.session.Session;
import net.java.otr4j.test.dummyclient.DummyClient;

import org.junit.Test;

/**
 * test that Socialist Millionaire Protocol verification is working
 *
 * @author Hans-Christoph Steiner
 */
public class SMPTest {

    @Test
    public void testGoodVerify() throws OtrException, IOException, InterruptedException {
        CountDownLatch aliceLock = new CountDownLatch(1);
        CountDownLatch bobLock = new CountDownLatch(1);
        DummyClient[] convo = DummyClient.getConversation(aliceLock, bobLock);
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];

        assertTrue(DummyClient.forceStartOtr(alice, bob));
        assertTrue(alice.getVerified() == DummyClient.NOTSET);
        assertTrue(bob.getVerified() == DummyClient.NOTSET);

        Session aliceSession = alice.getSession();
        Session bobSession = bob.getSession();

        assertFalse(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());
        aliceSession.initSmp(null, "goodPassword");

        assertTrue(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());
        bob.pollReceivedMessage(); // SMP1Q

        // wait for the password prompt that is triggered by: OtrEngineHost.askForSecret()
        bobLock.await(2000, TimeUnit.MILLISECONDS);

        bobSession.respondSmp(null, "goodPassword");
        assertTrue(aliceSession.isSmpInProgress());
        assertTrue(bobSession.isSmpInProgress());

        alice.pollReceivedMessage(); // SMP2
        assertTrue(aliceSession.isSmpInProgress());
        assertTrue(bobSession.isSmpInProgress());

        bob.pollReceivedMessage(); // SMP3
        assertTrue(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());

        alice.pollReceivedMessage(); // SMP4
        assertFalse(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());

        // wait for SMP to complete
        aliceLock.await(2000, TimeUnit.MILLISECONDS);
        // TODO this works until SMP3, then it dies
        assertTrue(alice.getVerified() == DummyClient.VERIFIED);
        assertTrue(bob.getVerified() == DummyClient.VERIFIED);
    }

    @Test
    public void testBadVerify() throws OtrException, IOException, InterruptedException {
        CountDownLatch aliceLock = new CountDownLatch(1);
        CountDownLatch bobLock = new CountDownLatch(1);
        DummyClient[] convo = DummyClient.getConversation(aliceLock, bobLock);
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];

        assertTrue(DummyClient.forceStartOtr(alice, bob));
        assertTrue(alice.getVerified() == DummyClient.NOTSET);
        assertTrue(bob.getVerified() == DummyClient.NOTSET);

        Session aliceSession = alice.getSession();
        Session bobSession = bob.getSession();

        assertFalse(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());
        aliceSession.initSmp(null, "goodPassword");

        assertTrue(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());
        bob.pollReceivedMessage(); // SMP1Q

        // wait for the password prompt that is triggered by: OtrEngineHost.askForSecret()
        bobLock.await(2000, TimeUnit.MILLISECONDS);

        bobSession.respondSmp(null, "badPassword");
        assertTrue(aliceSession.isSmpInProgress());
        assertTrue(bobSession.isSmpInProgress());

        alice.pollReceivedMessage(); // SMP2
        assertTrue(aliceSession.isSmpInProgress());
        assertTrue(bobSession.isSmpInProgress());

        bob.pollReceivedMessage(); // SMP3
        assertTrue(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());

        alice.pollReceivedMessage(); // SMP4
        assertFalse(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());

        // wait for SMP to complete
        aliceLock.await(2000, TimeUnit.MILLISECONDS);

        assertFalse(alice.getVerified() == DummyClient.VERIFIED);
        assertFalse(bob.getVerified() == DummyClient.VERIFIED);
    }
}
