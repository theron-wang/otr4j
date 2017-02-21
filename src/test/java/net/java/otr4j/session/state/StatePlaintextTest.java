package net.java.otr4j.session.state;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.io.messages.Message;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.OfferStatus;
import net.java.otr4j.session.Session.OTRv;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.TLV;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class StatePlaintextTest {

    private final SessionID sessionId = new SessionID("local", "remote", "xmpp");

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithViablePolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(
                new HashSet<>(Arrays.asList(OTRv.TWO, OTRv.THREE)),
                "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv2OnlyPolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(
                Collections.singleton(OTRv.TWO), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv3OnlyPolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(
                Collections.singleton(OTRv.THREE), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3 | OtrPolicy.SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithNonViablePolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(
                Collections.<Integer>emptySet(), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }

    @Test
    public void testTransformDoNotSendWhitespaceTag() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(
                Collections.<Integer>emptySet(), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }

    @Test
    public void testTransformAlreadySentWhitespaceTag() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage(
                Collections.<Integer>emptySet(), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.rejected);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }
}
