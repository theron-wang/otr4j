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
        OtrEngineHosts.onEvent(host, sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.VIOLATION);
        verify(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.VIOLATION);
    }

    @Test
    public void testSmpErrorOnFaultyHost() {
        final boolean cheated = true;
        final int type = 1;
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred"))
                .when(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.VIOLATION);
        OtrEngineHosts.onEvent(host, sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.VIOLATION);
        verify(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.VIOLATION);
    }

    @Test
    public void testSmpAbortedOnGoodHost() {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHosts.onEvent(host, sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.USER);
        verify(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.USER);
    }

    @Test
    public void testSmpAbortedOnFaultyHost() {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred"))
                .when(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.USER);
        OtrEngineHosts.onEvent(host, sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.USER);
        verify(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_ABORTED, EventAbortReason.USER);
    }

    @Test
    public void testVerifyOnGoodHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHosts.onEvent(host, sessionID, SMALLEST_TAG, Event.SMP_SUCCEEDED, fingerprint);
        verify(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_SUCCEEDED, fingerprint);
    }

    @Test
    public void testVerifyOnBadHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalStateException("some bad stuff happened"))
                .when(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_SUCCEEDED, fingerprint);
        OtrEngineHosts.onEvent(host, sessionID, SMALLEST_TAG, Event.SMP_SUCCEEDED, fingerprint);
        verify(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_SUCCEEDED, fingerprint);
    }

    @Test
    public void testUnverifyOnGoodHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHosts.onEvent(host, sessionID, SMALLEST_TAG, Event.SMP_FAILED, fingerprint);
        verify(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_FAILED, fingerprint);
    }

    @Test
    public void testUnverifyOnBadHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalStateException("some bad stuff happened"))
                .when(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_FAILED, fingerprint);
        OtrEngineHosts.onEvent(host, sessionID, SMALLEST_TAG, Event.SMP_FAILED, fingerprint);
        verify(host).onEvent(sessionID, SMALLEST_TAG, Event.SMP_FAILED, fingerprint);
    }

    @Test
    public void testAskForSecretOnGoodHost() {
        final String question = "What's my secret?";
        final InstanceTag sender = InstanceTag.random(RANDOM);
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHosts.onEvent(host, sessionID, sender, Event.SMP_REQUEST_SECRET, question);
        verify(host).onEvent(sessionID, sender, Event.SMP_REQUEST_SECRET, question);
    }

    @Test
    public void testAskForSecretOnFaultyHost() {
        final String question = "What's my secret?";
        final InstanceTag sender = InstanceTag.random(RANDOM);
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred"))
                .when(host).onEvent(sessionID, sender, Event.SMP_REQUEST_SECRET, question);
        OtrEngineHosts.onEvent(host, sessionID, sender, Event.SMP_REQUEST_SECRET, question);
        verify(host).onEvent(sessionID, sender, Event.SMP_REQUEST_SECRET, question);
    }
}
