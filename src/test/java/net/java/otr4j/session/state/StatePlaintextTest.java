package net.java.otr4j.session.state;

import java.util.Collections;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.session.OfferStatus;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.TLV;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.mockito.Mockito;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class StatePlaintextTest {

    private final SessionID sessionId = new SessionID("local", "remote", "xmpp");

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithViablePolicy() throws OtrException {
        final String[] expected = {
            "Hello world! \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t"
        };
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final String[] msgs = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertArrayEquals(expected, msgs);
        verify(context, atLeastOnce()).setOfferStatus(OfferStatus.sent);
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv2OnlyPolicy() throws OtrException {
        final String[] expected = {
            "Hello world! \t  \t\t\t\t \t \t \t    \t\t  \t "
        };
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final String[] msgs = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertArrayEquals(expected, msgs);
        verify(context, atLeastOnce()).setOfferStatus(OfferStatus.sent);
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv3OnlyPolicy() throws OtrException {
        final String[] expected = {
            "Hello world! \t  \t\t\t\t \t \t \t    \t\t  \t\t"
        };
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3 | OtrPolicy.SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final String[] msgs = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertArrayEquals(expected, msgs);
        verify(context, atLeastOnce()).setOfferStatus(OfferStatus.sent);
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithNonViablePolicy() throws OtrException {
        final String[] expected = {
            "Hello world!"
        };
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final String[] msgs = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertArrayEquals(expected, msgs);
        verify(context, never()).setOfferStatus(OfferStatus.sent);
    }

    @Test
    public void testTransformDoNotSendWhitespaceTag() throws OtrException {
        final String[] expected = {
            "Hello world!"
        };
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.idle);
        final String[] msgs = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertArrayEquals(expected, msgs);
        verify(context, never()).setOfferStatus(Mockito.any(OfferStatus.class));
    }

    @Test
    public void testTransformAlreadySentWhitespaceTag() throws OtrException {
        final String[] expected = {
            "Hello world!"
        };
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.rejected);
        final String[] msgs = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertArrayEquals(expected, msgs);
        verify(context, never()).setOfferStatus(Mockito.any(OfferStatus.class));
    }
}
