/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import org.junit.Test;

import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.Sessions.generateIdentifier;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("ConstantConditions")
public final class SessionsTest {

    @Test(expected = NullPointerException.class)
    public void testExtractIdentifierNull() {
        generateIdentifier(null);
    }

    @Test
    public void testExtractIdentifier() {
        final Session session = mock(Session.class);
        when(session.getSessionID()).thenReturn(new SessionID("alice", "bob", "network"));
        when(session.getReceiverInstanceTag()).thenReturn(SMALLEST_TAG);
        assertEquals("alice_network_bob, 256", generateIdentifier(session));
    }
}