package net.java.otr4j;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.java.otr4j.session.SessionID;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import org.junit.Before;
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

    private Level originalLoggingLevel;

    @Before
    public void setUp() {
        final Logger logger = Logger.getLogger("net.java.otr4j");
        originalLoggingLevel = logger.getLevel();
        logger.setLevel(Level.SEVERE);
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

    @Test(expected = OtrException.class)
    public void testUnencryptedMessageReceivedPassThroughOtrException() throws OtrException {
        final String msg = "Unencrypted message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new OtrException("expected error occurred")).when(host).unencryptedMessageReceived(sessionID, msg);
        OtrEngineHostUtil.unencryptedMessageReceived(host, sessionID, msg);
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

    @Test(expected = OtrException.class)
    public void testUnreadableMessageReceivedPassThroughOtrException() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new OtrException("expected error occurred")).when(host).unreadableMessageReceived(sessionID);
        OtrEngineHostUtil.unreadableMessageReceived(host, sessionID);
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
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).unreadableMessageReceived(sessionID);
        assertNull(OtrEngineHostUtil.getFallbackMessage(host, sessionID));
        verify(host).getFallbackMessage(sessionID);
    }
}
