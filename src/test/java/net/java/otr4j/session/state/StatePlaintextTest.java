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
import net.java.otr4j.api.Event;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.session.ake.StateInitial;
import net.java.otr4j.session.dake.DAKEInitial;
import net.java.otr4j.util.Unit;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.math.BigInteger.ZERO;
import static java.util.logging.Level.OFF;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.OfferStatus.IDLE;
import static net.java.otr4j.api.OfferStatus.REJECTED;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V3;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V4;
import static net.java.otr4j.api.OtrPolicy.OPPORTUNISTIC;
import static net.java.otr4j.api.OtrPolicy.REQUIRE_ENCRYPTION;
import static net.java.otr4j.api.OtrPolicy.SEND_WHITESPACE_TAG;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.api.Version.FOUR;
import static net.java.otr4j.api.Version.THREE;
import static net.java.otr4j.session.state.State.FLAG_IGNORE_UNREADABLE;
import static net.java.otr4j.session.state.State.FLAG_NONE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("ConstantConditions")
public class StatePlaintextTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final ClientProfileTestUtils PROFILE_UTILS = new ClientProfileTestUtils();

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithViablePolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(new HashSet<>(Arrays.asList(Version.TWO, Version.THREE, Version.FOUR)),
                "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final OtrPolicy policy = new OtrPolicy(OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv2OnlyPolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(Collections.singleton(Version.TWO), "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv3OnlyPolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(Collections.singleton(Version.THREE), "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final OtrPolicy policy = new OtrPolicy(ALLOW_V3 | SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test(expected = IllegalStateException.class)
    public void testTransformSendingEmbedWhitespaceTagWithNonViablePolicy() throws OtrException {
        final Logger logger = Logger.getLogger(OtrPolicy.class.getName());
        final Level original = logger.getLevel();
        try {
            logger.setLevel(OFF);
            final Context context = mock(Context.class);
            final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
            final OtrPolicy policy = new OtrPolicy(SEND_WHITESPACE_TAG);
            when(context.getSessionPolicy()).thenReturn(policy);
            when(context.getOfferStatus()).thenReturn(IDLE);
            state.transformSending(context, "Hello world!", Collections.emptyList(), FLAG_NONE);
        } finally {
            logger.setLevel(original);
        }
    }

    @Test
    public void testTransformDoNotSendWhitespaceTag() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(Collections.emptySet(), "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final OtrPolicy policy = new OtrPolicy(ALLOW_V3);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }

    @Test
    public void testTransformAlreadySentWhitespaceTag() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(Collections.emptySet(), "Hello world!");
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final OtrPolicy policy = new OtrPolicy(OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(REJECTED);
        final Message m = state.transformSending(context, "Hello world!", Collections.emptyList(), FLAG_NONE);
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }

    @Test(expected = OtrException.class)
    public void testTransformRequireEncryptionNoVersionSupported() throws OtrException {
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final OtrPolicy policy = new OtrPolicy(REQUIRE_ENCRYPTION);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(REJECTED);
        state.transformSending(context, "Hello world!", Collections.emptyList(), FLAG_NONE);
    }

    @Test
    public void testTransformRequireEncryption() throws OtrException {
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final OtrPolicy policy = new OtrPolicy(OPPORTUNISTIC | REQUIRE_ENCRYPTION);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(REJECTED);
        when(context.getHost()).thenReturn(mock(OtrEngineHost.class));
        when(context.getSessionID()).thenReturn(new SessionID("bob", "alice", "network"));
        assertNull(state.transformSending(context, "Hello world!", Collections.emptyList(), FLAG_NONE));
        verify(context).startSession();
    }

    @Test
    public void testEnd() {
        final Context context = mock(Context.class);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        state.end(context);
        verify(context, never()).transition(isA(State.class), isA(State.class));
    }

    @Test
    public void testDestroy() {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        state.destroy();
    }

    @Test
    public void testConstruct() {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        assertEquals(Version.NONE, state.getVersion());
        assertEquals(PLAINTEXT, state.getStatus());
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetSmpHandler() throws IncorrectStateException {
        new StatePlaintext(StateInitial.instance(), DAKEInitial.instance()).getSmpHandler();
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetRemotePublicKey() throws IncorrectStateException {
        new StatePlaintext(StateInitial.instance(), DAKEInitial.instance()).getRemoteInfo();
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetExtraSymmetricKey() throws IncorrectStateException {
        new StatePlaintext(StateInitial.instance(), DAKEInitial.instance()).getExtraSymmetricKey();
    }

    @Test
    public void testHandleDataMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(context.getReceiverInstanceTag()).thenReturn(SMALLEST_TAG);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final DHKeyPairOTR3 keypair = DHKeyPairOTR3.generateDHKeyPair(RANDOM);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final DataMessage message = new DataMessage(THREE, (byte) 0, 1, 1, keypair.getPublic(),
                new byte[16], new byte[0], new byte[20], new byte[0], SMALLEST_TAG, HIGHEST_TAG);
        assertNull(state.handleDataMessage(context, message).content);
        verify(host).handleEvent(eq(sessionID), eq(SMALLEST_TAG), eq(Event.UNREADABLE_MESSAGE_RECEIVED), eq(Unit.UNIT));
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
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final DataMessage message = new DataMessage(THREE, FLAG_IGNORE_UNREADABLE, 1, 1, keypair.getPublic(),
                new byte[16], new byte[0], new byte[20], new byte[0], SMALLEST_TAG, HIGHEST_TAG);
        assertNull(state.handleDataMessage(context, message).content);
        verify(host, never()).handleEvent(eq(sessionID), eq(SMALLEST_TAG), eq(Event.UNREADABLE_MESSAGE_RECEIVED), eq(Unit.UNIT));
        verify(context, never()).injectMessage(isA(ErrorMessage.class));
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessageNullContext() throws OtrException {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final DHKeyPairOTR3 keypair = DHKeyPairOTR3.generateDHKeyPair(RANDOM);
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
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

        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        state.handleDataMessage(context, (DataMessage) null);
    }

    @SuppressWarnings("resource")
    @Test
    public void testHandleDataMessage4() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(context.getReceiverInstanceTag()).thenReturn(SMALLEST_TAG);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdh.publicKey(), dh.publicKey(), new byte[80], new byte[64], new byte[0]);
        assertNull(state.handleDataMessage(context, message).content);
        verify(host).handleEvent(eq(sessionID), eq(SMALLEST_TAG), eq(Event.UNREADABLE_MESSAGE_RECEIVED), eq(Unit.UNIT));
        verify(context).injectMessage(isA(ErrorMessage.class));
    }

    @SuppressWarnings("resource")
    @Test
    public void testHandleDataMessage4IgnoreUnreadable() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(SMALLEST_TAG, HIGHEST_TAG, FLAG_IGNORE_UNREADABLE, 0, 0, 0,
                ecdh.publicKey(), dh.publicKey(), new byte[80], new byte[64], new byte[0]);
        assertNull(state.handleDataMessage(context, message).content);
        verify(host, never()).handleEvent(eq(sessionID), eq(SMALLEST_TAG), eq(Event.UNREADABLE_MESSAGE_RECEIVED), eq(Unit.UNIT));
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

        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        state.handleDataMessage(context, (DataMessage4) null);
    }

    @SuppressWarnings("resource")
    @Test(expected = NullPointerException.class)
    public void testHandleDataMessage4NullContext() throws OtrException {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdh.publicKey(), dh.publicKey(), new byte[80], new byte[64], new byte[0]);
        state.handleDataMessage(null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testHandleAKEMessageNonOTR4() throws OtrException, ProtocolException {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(ALLOW_V3);
        when(context.getSessionPolicy()).thenReturn(policy);
        state.handleEncodedMessage4(context, null);
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDAKEMessageNullContext() throws OtrException, ProtocolException {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final AbstractEncodedMessage message = mock(AbstractEncodedMessage.class);
        state.handleEncodedMessage4(null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDAKEMessageNullMessage() throws OtrException, ProtocolException {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(ALLOW_V4);
        when(context.getSessionPolicy()).thenReturn(policy);
        state.handleEncodedMessage4(context, null);
    }

    @SuppressWarnings("resource")
    @Test
    public void testHandleDAKEMessageIdentityMessage() throws OtrException, ProtocolException {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final Context context = mock(Context.class);
        when(context.secureRandom()).thenReturn(RANDOM);
        when(context.getSenderInstanceTag()).thenReturn(HIGHEST_TAG);
        when(context.getReceiverInstanceTag()).thenReturn(SMALLEST_TAG);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(context.getLongTermKeyPair()).thenReturn(longTermKeyPair);
        final ClientProfilePayload hostProfile = PROFILE_UTILS.createClientProfile();
        when(context.getClientProfilePayload()).thenReturn(hostProfile);
        final OtrPolicy policy = new OtrPolicy(ALLOW_V4);
        when(context.getSessionPolicy()).thenReturn(policy);
        final ClientProfilePayload profile = PROFILE_UTILS.createClientProfile();
        final ECDHKeyPair dakeECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dakeDH = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair firstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair firstDH = DHKeyPair.generate(RANDOM);
        final IdentityMessage message = new IdentityMessage(SMALLEST_TAG, HIGHEST_TAG, profile,
                dakeECDH.publicKey(), dakeDH.publicKey(), firstECDH.publicKey(), firstDH.publicKey());

        final State.Result result = state.handleEncodedMessage4(context, message);
        // FIXME test: check result values

        // Verify if correct return message was constructed, to a certain extent.
        final ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
        verify(context, times(1)).injectMessage(captor.capture());
        final AuthRMessage msg = (AuthRMessage) captor.getValue();
        assertEquals(FOUR, msg.protocolVersion);
        assertEquals(HIGHEST_TAG, msg.senderTag);
        assertEquals(SMALLEST_TAG, msg.receiverTag);
        assertEquals(hostProfile, msg.clientProfile);
    }

    @SuppressWarnings("resource")
    @Test
    public void testHandleDAKEMessageInvalidIdentityMessage() throws OtrException, ProtocolException {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(ALLOW_V4);
        when(context.getSessionPolicy()).thenReturn(policy);
        final ClientProfilePayload profile = PROFILE_UTILS.createClientProfile();
        final ECDHKeyPair dakeECDH = ECDHKeyPair.generate(RANDOM);
        final ECDHKeyPair firstECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair firstDH = DHKeyPair.generate(RANDOM);
        final IdentityMessage message = new IdentityMessage(SMALLEST_TAG, HIGHEST_TAG, profile,
                dakeECDH.publicKey(), ZERO, firstECDH.publicKey(), firstDH.publicKey());
        state.handleEncodedMessage4(context, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHandleDAKEMessageInvalidMessageType() throws OtrException, ProtocolException {
        final StatePlaintext state = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(ALLOW_V4);
        when(context.getSessionPolicy()).thenReturn(policy);
        state.handleEncodedMessage4(context, new DHCommitMessage(THREE, new byte[0], new byte[0], SMALLEST_TAG, HIGHEST_TAG));
    }
}
