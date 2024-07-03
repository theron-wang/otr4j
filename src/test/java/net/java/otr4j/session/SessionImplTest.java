/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.QueryMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.state.State;
import net.java.otr4j.util.Classes;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.net.ProtocolException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;

import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.OtrPolicy.OPPORTUNISTIC;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("ConstantConditions")
public final class SessionImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testTransitionFromNullState() {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final EdDSAKeyPair forgingKey = EdDSAKeyPair.generate(RANDOM);
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(forgingKey);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        final SessionImpl session = new SessionImpl(sessionID, host);
        session.transition(null, mock(State.class));
    }

    @Test(expected = NullPointerException.class)
    public void testTransitionToNullState() {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final EdDSAKeyPair forgingKey = EdDSAKeyPair.generate(RANDOM);
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(forgingKey);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        final SessionImpl session = new SessionImpl(sessionID, host);
        session.transition(Classes.readField(State.class, session, "sessionState"), null);
    }

    @Test
    public void testTransitionDestroysPreviousState() {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final EdDSAKeyPair forgingKey = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair legacyKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getSessionPolicy(eq(sessionID))).thenReturn(new OtrPolicy(OPPORTUNISTIC));
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(forgingKey);
        when(host.getLocalKeyPair(eq(sessionID))).thenReturn(legacyKeyPair);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        final SessionImpl session = new SessionImpl(sessionID, host);
        final State secondState = mock(State.class);
        session.transition(Classes.readField(State.class, session, "sessionState"), secondState);
        verify(secondState, times(0)).destroy();
        session.transition(secondState, mock(State.class));
        verify(secondState, times(1)).destroy();
    }

    @Test
    public void testTransitionToSecureSessionCallsSessionStatusChanged() {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final EdDSAKeyPair forgingKey = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair legacyKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getSessionPolicy(eq(sessionID))).thenReturn(new OtrPolicy(OPPORTUNISTIC));
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(forgingKey);
        when(host.getLocalKeyPair(eq(sessionID))).thenReturn(legacyKeyPair);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        final SessionImpl session = new SessionImpl(sessionID, host);
        final OtrEngineListener listener = mock(OtrEngineListener.class);
        session.addOtrEngineListener(listener);
        final State secondState = mock(State.class);
        when(secondState.getStatus()).thenReturn(ENCRYPTED);
        session.transition(Classes.readField(State.class, session, "sessionState"), secondState);
        // Testing with master session here for simplicity, so not completely representative, but does confirm that
        // sessionStatusChanged is called.
        verify(listener, times(1)).sessionStatusChanged(eq(sessionID), eq(ZERO_TAG));
    }

    @Test
    public void testInjectingQueryTagWithFallbackMessageTooLarge() throws OtrException {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final EdDSAKeyPair forgingKey = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair legacyKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getSessionPolicy(eq(sessionID))).thenReturn(new OtrPolicy(OPPORTUNISTIC));
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(forgingKey);
        when(host.getLocalKeyPair(eq(sessionID))).thenReturn(legacyKeyPair);
        when(host.getFallbackMessage(sessionID)).thenReturn("This is a super-long message that does not fit on the transport channel.");
        when(host.getMaxFragmentSize(sessionID)).thenReturn(51);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        final SessionImpl session = new SessionImpl(sessionID, host);
        final EnumSet<Version> versions = EnumSet.of(Version.THREE, Version.FOUR);
        session.injectMessage(new QueryMessage(versions));
        verify(host).injectMessage(sessionID, "?OTRv34? This is a super-long message that does not");
    }

    @Test
    public void testRefreshingExpiredClientProfile() throws OtrException, InterruptedException, ProtocolException {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final EdDSAKeyPair forgingKey = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair legacyKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final ClientProfile profile = new ClientProfile(InstanceTag.SMALLEST_TAG, longTermKeyPair.getPublicKey(),
                forgingKey.getPublicKey(), List.of(Version.FOUR), null);
        when(host.getSessionPolicy(eq(sessionID))).thenReturn(new OtrPolicy(OPPORTUNISTIC));
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(forgingKey);
        when(host.getLocalKeyPair(eq(sessionID))).thenReturn(legacyKeyPair);
        final long delay = 3000;
        final ClientProfilePayload expiringPayload = ClientProfilePayload.signClientProfile(profile,
                Instant.now().plusSeconds(delay/1000).getEpochSecond(), null, longTermKeyPair);
        final OtrOutputStream serialized = new OtrOutputStream();
        expiringPayload.writeTo(serialized);
        when(host.restoreClientProfilePayload()).thenReturn(serialized.toByteArray());
        final SessionImpl session = new SessionImpl(sessionID, host);
        Thread.sleep(delay);
        final ClientProfilePayload[] container = Classes.readField(ClientProfilePayload[].class, session, "profilePayload");
        try {
            container[0].validate();
            fail("Stored profile-payload is expected to be expired.");
        } catch (final ValidationException e) {
            // Expect validation failure.
        }
        // Sleeping to ensure that the profile expires.
        assertNotNull(session.getClientProfilePayload().validate());
        // Now acquire the refreshed client-profile bytes and ensure that it is valid.
        final ArgumentCaptor<byte[]> payloadCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(host, times(1)).updateClientProfilePayload(payloadCaptor.capture());
        final byte[] payloadbytes = payloadCaptor.getValue();
        final ClientProfilePayload payload = ClientProfilePayload.readFrom(new OtrInputStream(payloadbytes));
        assertFalse(payload.expired(Instant.now()));
        assertNotNull(payload.validate());
    }
}