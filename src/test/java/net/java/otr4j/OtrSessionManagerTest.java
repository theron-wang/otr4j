/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

/**
 * Tests for OtrSessionManager.
 *
 * @author Danny van Heumen
 */
public class OtrSessionManagerTest {

    @Test
    public void testGetSession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        final SessionID sid = new SessionID("user", "dude", "xmpp");
        final Session first = mgr.getSession(sid);
        assertNotNull(first);
        assertEquals(sid, first.getSessionID());
        final Session second = mgr.getSession(sid);
        assertSame(first, second);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetNullSession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.getSession(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetEmptySession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.getSession(SessionID.EMPTY);
    }
}
