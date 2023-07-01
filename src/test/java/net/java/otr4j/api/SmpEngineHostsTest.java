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

import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SmpEngineHostsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Level originalLoggingLevel;

    @Before
    public void setUp() {
        final Logger globalLogger = Logger.getLogger(OtrEngineHosts.class.getName());
        this.originalLoggingLevel = globalLogger.getLevel();
        globalLogger.setLevel(Level.OFF);
    }

    @After
    public void tearDown() {
        Logger.getLogger(OtrEngineHosts.class.getName()).setLevel(this.originalLoggingLevel);
    }

    @Test
    public void testSmpErrorOnGoodHost() {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHosts.handleEvent(host, sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.VIOLATION);
        verify(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.VIOLATION);
    }

    @Test
    public void testSmpErrorOnFaultyHost() {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred"))
                .when(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.VIOLATION);
        OtrEngineHosts.handleEvent(host, sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.VIOLATION);
        verify(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.VIOLATION);
    }

    @Test
    public void testSmpAbortedOnGoodHost() {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHosts.handleEvent(host, sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.USER);
        verify(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.USER);
    }

    @Test
    public void testSmpAbortedOnFaultyHost() {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred"))
                .when(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.USER);
        OtrEngineHosts.handleEvent(host, sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.USER);
        verify(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, Event.AbortReason.USER);
    }

    @Test
    public void testVerifyOnGoodHost() {
        final byte[] fingerprint = "myfingerprint".getBytes(UTF_8);
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final Event.SMPResult result = new Event.SMPResult(true, fingerprint);
        OtrEngineHosts.handleEvent(host, sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
        verify(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
    }

    @Test
    public void testVerifyOnBadHost() {
        final byte[] fingerprint = "myfingerprint".getBytes(UTF_8);
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final Event.SMPResult result = new Event.SMPResult(true, fingerprint);
        doThrow(new IllegalStateException("some bad stuff happened"))
                .when(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
        OtrEngineHosts.handleEvent(host, sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
        verify(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
    }

    @Test
    public void testUnverifyOnGoodHost() {
        final byte[] fingerprint = "myfingerprint".getBytes(UTF_8);
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final Event.SMPResult result = new Event.SMPResult(true, fingerprint);
        OtrEngineHosts.handleEvent(host, sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
        verify(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
    }

    @Test
    public void testUnverifyOnBadHost() {
        final byte[] fingerprint = "myfingerprint".getBytes(UTF_8);
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final Event.SMPResult result = new Event.SMPResult(true, fingerprint);
        doThrow(new IllegalStateException("some bad stuff happened"))
                .when(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
        OtrEngineHosts.handleEvent(host, sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
        verify(host).handleEvent(sessionID, SMALLEST_TAG, Event.SMP_COMPLETED, result);
    }

    @Test
    public void testAskForSecretOnGoodHost() {
        final String question = "What's my secret?";
        final InstanceTag sender = InstanceTag.random(RANDOM);
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHosts.handleEvent(host, sessionID, sender, Event.SMP_REQUEST_SECRET, question);
        verify(host).handleEvent(sessionID, sender, Event.SMP_REQUEST_SECRET, question);
    }

    @Test
    public void testAskForSecretOnFaultyHost() {
        final String question = "What's my secret?";
        final InstanceTag sender = InstanceTag.random(RANDOM);
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred"))
                .when(host).handleEvent(sessionID, sender, Event.SMP_REQUEST_SECRET, question);
        OtrEngineHosts.handleEvent(host, sessionID, sender, Event.SMP_REQUEST_SECRET, question);
        verify(host).handleEvent(sessionID, sender, Event.SMP_REQUEST_SECRET, question);
    }
}
