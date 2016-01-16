package net.java.otr4j;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.java.otr4j.session.SessionID;
import org.junit.After;
import org.junit.Test;
import org.junit.Before;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

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
}
