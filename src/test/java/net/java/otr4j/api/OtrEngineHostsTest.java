/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.api.OtrEngineHosts.getReplyForUnreadableMessage;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for OtrEngineHostUtil utilities.
 *
 * @author Danny van Heumen
 */
public class OtrEngineHostsTest {

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
    public void testGetFallbackMessageOnGoodHost() {
        final String fallbackMessage = "Hey dude, get OTR to talk to me!";
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getFallbackMessage(sessionID)).thenReturn(fallbackMessage);
        assertEquals(fallbackMessage, OtrEngineHosts.getFallbackMessage(host, sessionID));
        verify(host).getFallbackMessage(sessionID);
    }

    @Test
    public void testGetFallbackMessageOnFaultyHost() {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getFallbackMessage(sessionID)).thenReturn("Hey dude, get OTR to talk to me!");
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).getFallbackMessage(sessionID);
        assertNull(OtrEngineHosts.getFallbackMessage(host, sessionID));
        verify(host).getFallbackMessage(sessionID);
    }

    @Test
    public void testGetReplyForUnreadableMessageOnGoodHost() {
        final String replyMsg = "Hey dude, I can't ready you're message!";
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getReplyForUnreadableMessage(sessionID, "")).thenReturn(replyMsg);
        assertEquals(replyMsg, getReplyForUnreadableMessage(host, sessionID, "", "default message"));
        verify(host).getReplyForUnreadableMessage(sessionID, "");
    }

    @Test
    public void testGetReplyForUnreadableMessageOnFaultyHost() {
        final String defaultMessage = "This message cannot be read.";
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).getReplyForUnreadableMessage(sessionID, "");
        assertEquals(defaultMessage, getReplyForUnreadableMessage(host, sessionID, "", defaultMessage));
        verify(host).getReplyForUnreadableMessage(sessionID, "");
    }
}
