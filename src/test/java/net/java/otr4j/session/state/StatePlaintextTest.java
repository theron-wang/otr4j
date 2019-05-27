/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.StateInitial;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Level.OFF;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.OfferStatus.IDLE;
import static net.java.otr4j.api.OfferStatus.REJECTED;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V3;
import static net.java.otr4j.api.OtrPolicy.OPPORTUNISTIC;
import static net.java.otr4j.api.OtrPolicy.REQUIRE_ENCRYPTION;
import static net.java.otr4j.api.OtrPolicy.SEND_WHITESPACE_TAG;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.Session.Version.THREE;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.session.state.State.FLAG_IGNORE_UNREADABLE;
import static net.java.otr4j.session.state.State.FLAG_NONE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("ConstantConditions")
public class StatePlaintextTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithViablePolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(new HashSet<>(Arrays.asList(Version.TWO, Version.THREE, Version.FOUR)),
                "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        final OtrPolicy policy = new OtrPolicy(OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv2OnlyPolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(Collections.singleton(Version.TWO), "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv3OnlyPolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(Collections.singleton(Version.THREE), "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        final OtrPolicy policy = new OtrPolicy(ALLOW_V3 | SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test(expected = IllegalStateException.class)
    public void testTransformSendingEmbedWhitespaceTagWithNonViablePolicy() throws OtrException {
        final Logger logger = Logger.getLogger(OtrPolicy.class.getName());
        final Level original = logger.getLevel();
        try {
            logger.setLevel(OFF);
            final PlainTextMessage expected = new PlainTextMessage(Collections.<Integer>emptySet(), "Hello world!");
            final Context context = mock(Context.class);
            final StatePlaintext state = new StatePlaintext(StateInitial.instance());
            final OtrPolicy policy = new OtrPolicy(SEND_WHITESPACE_TAG);
            when(context.getSessionPolicy()).thenReturn(policy);
            when(context.getOfferStatus()).thenReturn(IDLE);
            state.transformSending(context, "Hello world!", Collections.<TLV>emptyList(), FLAG_NONE);
        } finally {
            logger.setLevel(original);
        }
    }

    @Test
    public void testTransformDoNotSendWhitespaceTag() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(Collections.<Integer>emptySet(), "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        final OtrPolicy policy = new OtrPolicy(ALLOW_V3);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }

    @Test
    public void testTransformAlreadySentWhitespaceTag() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(Collections.<Integer>emptySet(), "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        final OtrPolicy policy = new OtrPolicy(OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(REJECTED);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }

    @Test(expected = OtrException.class)
    public void testTransformRequireEncryptionNoVersionSupported() throws OtrException {
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        final OtrPolicy policy = new OtrPolicy(REQUIRE_ENCRYPTION);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(REJECTED);
        state.transformSending(context, "Hello world!", Collections.<TLV>emptyList(), FLAG_NONE);
    }

    @Test
    public void testTransformRequireEncryption() throws OtrException {
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        final OtrPolicy policy = new OtrPolicy(OPPORTUNISTIC | REQUIRE_ENCRYPTION);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(REJECTED);
        when(context.getHost()).thenReturn(mock(OtrEngineHost.class));
        when(context.getSessionID()).thenReturn(new SessionID("bob", "alice", "network"));
        assertNull(state.transformSending(context, "Hello world!", Collections.<TLV>emptyList(), FLAG_NONE));
        verify(context).startSession();
        verify(context).queueMessage(eq("Hello world!"));
    }

    @Test
    public void testEnd() {
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        state.end(context);
        verify(context, never()).transition(any(State.class), any(State.class));
    }

    @Test
    public void testDestroy() {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        state.destroy();
    }

    @Test
    public void testConstruct() {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        assertEquals(0, state.getVersion());
        assertEquals(PLAINTEXT, state.getStatus());
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetSmpHandler() throws IncorrectStateException {
        new StatePlaintext(StateInitial.instance()).getSmpHandler();
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetRemotePublicKey() throws IncorrectStateException {
        new StatePlaintext(StateInitial.instance()).getRemotePublicKey();
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetExtraSymmetricKey() throws IncorrectStateException {
        new StatePlaintext(StateInitial.instance()).getExtraSymmetricKey();
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
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
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
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
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
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
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

        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
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

        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
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

        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
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

        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        state.handleDataMessage(context, (DataMessage4) null);
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessage4NullContext() throws OtrException {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(FOUR, SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdh.getPublicKey(), dh.getPublicKey(), new byte[80], new byte[64], new byte[0]);
        state.handleDataMessage(null, message);
    }
}
