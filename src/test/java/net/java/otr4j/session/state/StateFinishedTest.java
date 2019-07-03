/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfileTestUtils;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Ed448;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.RevealSignatureMessage;
import net.java.otr4j.session.ake.StateInitial;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Collections;

import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.Session.Version.THREE;
import static net.java.otr4j.api.SessionStatus.FINISHED;
import static net.java.otr4j.session.state.State.FLAG_IGNORE_UNREADABLE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("ConstantConditions")
public class StateFinishedTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final ClientProfileTestUtils UTILS = new ClientProfileTestUtils();

    @Test(expected = NullPointerException.class)
    public void testConstructNullAuthState() {
        new StateFinished(null);
    }

    @Test
    public void testConstruct() {
        new StateFinished(StateInitial.instance());
    }

    @Test
    public void testExpectProtocolVersionIsZero() {
        final StateFinished state = new StateFinished(StateInitial.instance());
        assertEquals(0, state.getVersion());
        assertEquals(FINISHED, state.getStatus());
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetSMPHandlerFails() throws IncorrectStateException {
        final StateFinished state = new StateFinished(StateInitial.instance());
        state.getSmpHandler();
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetExtraSymmetricKeyFails() throws IncorrectStateException {
        final StateFinished state = new StateFinished(StateInitial.instance());
        state.getExtraSymmetricKey();
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetRemotePublicKeyFails() throws IncorrectStateException {
        final StateFinished state = new StateFinished(StateInitial.instance());
        state.getRemotePublicKey();
    }

    @Test
    public void testDestroy() {
        new StateFinished(StateInitial.instance()).destroy();
    }

    @Test
    public void testEnd() {
        final Context context = mock(Context.class);
        final StateFinished state = new StateFinished(StateInitial.instance());
        state.end(context);
        verify(context).transition(eq(state), isA(StatePlaintext.class));
    }

    @Test
    public void testHandlePlaintextMessage() {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        final PlainTextMessage message = new PlainTextMessage(Collections.<Integer>emptySet(), "Hello world!");
        final StateFinished state = new StateFinished(StateInitial.instance());
        assertEquals("Hello world!", state.handlePlainTextMessage(context, message));
        verify(host).unencryptedMessageReceived(eq(sessionID), eq("Hello world!"));
    }

    @Test(expected = NullPointerException.class)
    public void testHandlePlaintextMessageNullMessage() {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        final StateFinished state = new StateFinished(StateInitial.instance());
        state.handlePlainTextMessage(context, null);
    }

    @Test(expected = NullPointerException.class)
    public void testHandlePlaintextMessageNullContext() {
        final PlainTextMessage message = new PlainTextMessage(Collections.<Integer>emptySet(), "Hello world!");
        final StateFinished state = new StateFinished(StateInitial.instance());
        state.handlePlainTextMessage(null, message);
    }

    @Test
    public void testTransformSending() {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        final StateFinished state = new StateFinished(StateInitial.instance());
        assertNull(state.transformSending(context, "Hello world!", Collections.<TLV>emptySet(), (byte) 0));
        verify(context).queueMessage(eq("Hello world!"));
        verify(host).finishedSessionMessage(eq(sessionID), eq("Hello world!"));
    }

    @Test(expected = NullPointerException.class)
    public void testTransformSendingNullMessage() {
        final Context context = mock(Context.class);
        doThrow(NullPointerException.class).when(context).queueMessage(null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        final StateFinished state = new StateFinished(StateInitial.instance());
        assertNull(state.transformSending(context, null, Collections.<TLV>emptySet(), (byte) 0));
    }

    @Test(expected = NullPointerException.class)
    public void testTransformSendingNullContext() {
        final StateFinished state = new StateFinished(StateInitial.instance());
        assertNull(state.transformSending(null, "Hello world!", Collections.<TLV>emptySet(), (byte) 0));
    }

    @Test
    public void testHandleDataMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final DHKeyPairOTR3 keypair = DHKeyPairOTR3.generateDHKeyPair(RANDOM);
        final StateFinished state = new StateFinished(StateInitial.instance());
        final DataMessage message = new DataMessage(THREE, (byte) 0, 1, 1, keypair.getPublic(),
                new byte[16], new byte[0], new byte[20], new byte[0], SMALLEST_TAG, HIGHEST_TAG);
        assertNull(state.handleDataMessage(context, message));
        verify(host).unreadableMessageReceived(eq(sessionID));
        verify(context).injectMessage(isA(ErrorMessage.class));
    }

    @Test
    public void testHandleDataMessageIgnoreUnreadable() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final DHKeyPairOTR3 keypair = DHKeyPairOTR3.generateDHKeyPair(RANDOM);
        final StateFinished state = new StateFinished(StateInitial.instance());
        final DataMessage message = new DataMessage(THREE, FLAG_IGNORE_UNREADABLE, 1, 1, keypair.getPublic(),
                new byte[16], new byte[0], new byte[20], new byte[0], SMALLEST_TAG, HIGHEST_TAG);
        assertNull(state.handleDataMessage(context, message));
        verify(host, never()).unreadableMessageReceived(eq(sessionID));
        verify(context, never()).injectMessage(isA(ErrorMessage.class));
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessageNullContext() throws OtrException {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final DHKeyPairOTR3 keypair = DHKeyPairOTR3.generateDHKeyPair(RANDOM);
        final StateFinished state = new StateFinished(StateInitial.instance());
        final DataMessage message = new DataMessage(THREE, (byte) 0, 1, 1, keypair.getPublic(),
                new byte[16], new byte[0], new byte[20], new byte[0], SMALLEST_TAG, HIGHEST_TAG);
        state.handleDataMessage(null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessageNullMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance());
        state.handleDataMessage(context, (DataMessage) null);
    }

    @Test
    public void testHandleDataMessage4() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(FOUR, SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdh.getPublicKey(), dh.getPublicKey(), new byte[80], new byte[64], new byte[0]);
        assertNull(state.handleDataMessage(context, message));
        verify(host).unreadableMessageReceived(eq(sessionID));
        verify(context).injectMessage(isA(ErrorMessage.class));
    }

    @Test
    public void testHandleDataMessage4IgnoreUnreadable() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(FOUR, SMALLEST_TAG, HIGHEST_TAG, FLAG_IGNORE_UNREADABLE, 0, 0, 0,
                ecdh.getPublicKey(), dh.getPublicKey(), new byte[80], new byte[64], new byte[0]);
        assertNull(state.handleDataMessage(context, message));
        verify(host, never()).unreadableMessageReceived(eq(sessionID));
        verify(context, never()).injectMessage(isA(ErrorMessage.class));
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessage4NullMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance());
        state.handleDataMessage(context, (DataMessage4) null);
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessage4NullContext() throws OtrException {
        final StateFinished state = new StateFinished(StateInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(FOUR, SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdh.getPublicKey(), dh.getPublicKey(), new byte[80], new byte[64], new byte[0]);
        state.handleDataMessage(null, message);
    }

    @Test
    public void testHandleAKEMessageNonIdentityMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance());
        state.handleAKEMessage(context, new RevealSignatureMessage(THREE, new byte[0], new byte[0], new byte[0], SMALLEST_TAG, HIGHEST_TAG));
    }

    @Test
    public void testHandleAKEMessageIdentityMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        when(context.secureRandom()).thenReturn(RANDOM);
        when(context.getSenderInstanceTag()).thenReturn(SMALLEST_TAG);
        when(context.getReceiverInstanceTag()).thenReturn(HIGHEST_TAG);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(EdDSAKeyPair.generate(RANDOM));
        final ClientProfilePayload profile = UTILS.createClientProfile();
        when(context.getClientProfilePayload()).thenReturn(profile);
        final StateFinished state = new StateFinished(StateInitial.instance());
        final ECDHKeyPair ecdh1 = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh1 = DHKeyPair.generate(RANDOM);
        final DHKeyPair dh2 = DHKeyPair.generate(RANDOM);


        state.handleAKEMessage(context, new IdentityMessage(FOUR, SMALLEST_TAG, HIGHEST_TAG, profile,
                Ed448.identity(), dh1.getPublicKey(), ecdh1.getPublicKey(), dh2.getPublicKey()));
        verify(context, never()).injectMessage(isA(AuthRMessage.class));
        verify(context, never()).transition(eq(state), isA(StateAwaitingAuthI.class));
    }
}