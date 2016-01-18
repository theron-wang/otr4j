package net.java.otr4j;

import java.util.Arrays;
import net.java.otr4j.session.SessionID;
import org.junit.Test;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class OtrKeyManagerListenerUtilTest {

    @Test
    public void testPropagateEventOverGoodListeners() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrKeyManagerListener l1 = mock(OtrKeyManagerListener.class);
        final OtrKeyManagerListener l2 = mock(OtrKeyManagerListener.class);
        OtrKeyManagerListenerUtil.verificationStatusChanged(Arrays.asList(l1, l2), sessionID);
        verify(l1).verificationStatusChanged(sessionID);
        verify(l2).verificationStatusChanged(sessionID);
    }

    @Test
    public void testPropagateEventOverSomeBadListeners() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrKeyManagerListener l1 = mock(OtrKeyManagerListener.class);
        final OtrKeyManagerListener l2 = mock(OtrKeyManagerListener.class);
        doThrow(new IllegalStateException("bad stuff happened")).when(l1).verificationStatusChanged(sessionID);
        OtrKeyManagerListenerUtil.verificationStatusChanged(Arrays.asList(l1, l2), sessionID);
        verify(l1).verificationStatusChanged(sessionID);
        verify(l2).verificationStatusChanged(sessionID);
    }
}
