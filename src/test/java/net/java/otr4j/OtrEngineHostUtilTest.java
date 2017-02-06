/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.SessionID;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.Test;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for OtrEngineHostUtil utilities.
 *
 * @author Danny van Heumen
 */
public class OtrEngineHostUtilTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Level originalLoggingLevel;

    @Before
    public void setUp() {
        final Logger logger = Logger.getLogger("net.java.otr4j");
        originalLoggingLevel = logger.getLevel();
        logger.setLevel(Level.OFF);
    }

    @After
    public void tearDown() {
        Logger.getLogger("net.java.otr4j").setLevel(originalLoggingLevel);
    }

    @Test
    public void testMultipleInstancesDetectedOnGoodHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.multipleInstancesDetected(host, sessionID);
        verify(host).multipleInstancesDetected(sessionID);
    }

    @Test
    public void testMultipleInstancesDetectedOnFaultyHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).multipleInstancesDetected(sessionID);
        OtrEngineHostUtil.multipleInstancesDetected(host, sessionID);
        verify(host).multipleInstancesDetected(sessionID);
    }

    @Test
    public void testMessageFromAnotherInstanceReceivedOnGoodHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.messageFromAnotherInstanceReceived(host, sessionID);
        verify(host).messageFromAnotherInstanceReceived(sessionID);
    }

    @Test
    public void testMessageFromAnotherInstanceReceivedOnFaultyHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).messageFromAnotherInstanceReceived(sessionID);
        OtrEngineHostUtil.messageFromAnotherInstanceReceived(host, sessionID);
        verify(host).messageFromAnotherInstanceReceived(sessionID);
    }

    @Test
    public void testUnencryptedMessageReceivedOnGoodHost() throws OtrException {
        final String msg = "Unencrypted message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.unencryptedMessageReceived(host, sessionID, msg);
        verify(host).unencryptedMessageReceived(sessionID, msg);
    }

    @Test
    public void testUnencryptedMessageReceivedOnFaultyHost() throws OtrException {
        final String msg = "Unencrypted message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).unencryptedMessageReceived(sessionID, msg);
        OtrEngineHostUtil.unencryptedMessageReceived(host, sessionID, msg);
        verify(host).unencryptedMessageReceived(sessionID, msg);
    }

    @Test
    public void testUnreadableMessageReceivedOnGoodHost() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.unreadableMessageReceived(host, sessionID);
        verify(host).unreadableMessageReceived(sessionID);
    }

    @Test
    public void testUnreadableMessageReceivedOnFaultyHost() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).unreadableMessageReceived(sessionID);
        OtrEngineHostUtil.unreadableMessageReceived(host, sessionID);
        verify(host).unreadableMessageReceived(sessionID);
    }

    @Test
    public void testGetFallbackMessageOnGoodHost() throws OtrException {
        final String fallbackMessage = "Hey dude, get OTR to talk to me!";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getFallbackMessage(sessionID)).thenReturn(fallbackMessage);
        assertEquals(fallbackMessage, OtrEngineHostUtil.getFallbackMessage(host, sessionID));
        verify(host).getFallbackMessage(sessionID);
    }

    @Test
    public void testGetFallbackMessageOnFaultyHost() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getFallbackMessage(sessionID)).thenReturn("Hey dude, get OTR to talk to me!");
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).getFallbackMessage(sessionID);
        assertNull(OtrEngineHostUtil.getFallbackMessage(host, sessionID));
        verify(host).getFallbackMessage(sessionID);
    }

    @Test
    public void testVerifyOnGoodHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.verify(host, sessionID, fingerprint);
        verify(host).verify(sessionID, fingerprint);
    }

    @Test
    public void testVerifyOnBadHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalStateException("some bad stuff happened")).when(host).verify(sessionID, fingerprint);
        OtrEngineHostUtil.verify(host, sessionID, fingerprint);
        verify(host).verify(sessionID, fingerprint);
    }

    @Test
    public void testUnverifyOnGoodHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.unverify(host, sessionID, fingerprint);
        verify(host).unverify(sessionID, fingerprint);
    }

    @Test
    public void testUnverifyOnBadHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalStateException("some bad stuff happened")).when(host).unverify(sessionID, fingerprint);
        OtrEngineHostUtil.unverify(host, sessionID, fingerprint);
        verify(host).unverify(sessionID, fingerprint);
    }

    @Test
    public void testShowErrorOnGoodHost() throws OtrException {
        final String error = "My error message.";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.showError(host, sessionID, error);
        verify(host).showError(sessionID, error);
    }

    @Test
    public void testShowErrorOnFaultyHost() throws OtrException {
        final String error = "My error message.";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).showError(sessionID, error);
        OtrEngineHostUtil.showError(host, sessionID, error);
        verify(host).showError(sessionID, error);
    }

    @Test
    public void testSmpErrorOnGoodHost() throws OtrException {
        final boolean cheated = true;
        final int type = 1;
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.smpError(host, sessionID, type, cheated);
        verify(host).smpError(sessionID, type, cheated);
    }

    @Test
    public void testSmpErrorOnFaultyHost() throws OtrException {
        final boolean cheated = true;
        final int type = 1;
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).smpError(sessionID, type, cheated);
        OtrEngineHostUtil.smpError(host, sessionID, type, cheated);
        verify(host).smpError(sessionID, type, cheated);
    }

    @Test
    public void testSmpAbortedOnGoodHost() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.smpAborted(host, sessionID);
        verify(host).smpAborted(sessionID);
    }

    @Test
    public void testSmpAbortedOnFaultyHost() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).smpAborted(sessionID);
        OtrEngineHostUtil.smpAborted(host, sessionID);
        verify(host).smpAborted(sessionID);
    }

    @Test
    public void testFinishedSessionMessageOnGoodHost() throws OtrException {
        final String msg = "My session finished message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.finishedSessionMessage(host, sessionID, msg);
        verify(host).finishedSessionMessage(sessionID, msg);
    }

    @Test
    public void testFinishedSessionMessageOnFaultyHost() throws OtrException {
        final String msg = "My session finished message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).finishedSessionMessage(sessionID, msg);
        OtrEngineHostUtil.finishedSessionMessage(host, sessionID, msg);
        verify(host).finishedSessionMessage(sessionID, msg);
    }

    @Test
    public void testRequireEncryptedMessageOnGoodHost() throws OtrException {
        final String msg = "I require encryption";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.requireEncryptedMessage(host, sessionID, msg);
        verify(host).requireEncryptedMessage(sessionID, msg);
    }

    @Test
    public void testRequireEncryptedMessageOnFaultyHost() throws OtrException {
        final String msg = "I require encryption";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).requireEncryptedMessage(sessionID, msg);
        OtrEngineHostUtil.requireEncryptedMessage(host, sessionID, msg);
        verify(host).requireEncryptedMessage(sessionID, msg);
    }

    @Test
    public void testAskForSecretOnGoodHost() throws OtrException {
        final String question = "What's my secret?";
        final InstanceTag sender = InstanceTag.random(RANDOM);
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.askForSecret(host, sessionID, sender, question);
        verify(host).askForSecret(sessionID, sender, question);
    }

    @Test
    public void testAskForSecretOnFaultyHost() throws OtrException {
        final String question = "What's my secret?";
        final InstanceTag sender = InstanceTag.random(RANDOM);
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).askForSecret(sessionID, sender, question);
        OtrEngineHostUtil.askForSecret(host, sessionID, sender, question);
        verify(host).askForSecret(sessionID, sender, question);
    }

    @Test
    public void testGetReplyForUnreadableMessageOnGoodHost() throws OtrException {
        final String replyMsg = "Hey dude, I can't ready you're message!";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getReplyForUnreadableMessage(sessionID)).thenReturn(replyMsg);
        assertEquals(replyMsg, OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionID, "default message"));
        verify(host).getReplyForUnreadableMessage(sessionID);
    }

    @Test
    public void testGetReplyForUnreadableMessageOnFaultyHost() throws OtrException {
        final String defaultMessage = "This message cannot be read.";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).getReplyForUnreadableMessage(sessionID);
        assertEquals(defaultMessage, OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionID, defaultMessage));
        verify(host).getReplyForUnreadableMessage(sessionID);
    }
}
