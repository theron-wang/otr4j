/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.session.state.IncorrectStateException;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TimerTask;
import java.util.logging.Logger;

import static java.util.Collections.synchronizedList;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.Sessions.generateIdentifier;

final class SessionExpirationTimerTask extends TimerTask {

    private static final Logger LOGGER = Logger.getLogger(SessionExpirationTimerTask.class.getName());

    private static final SessionExpirationTimerTask INSTANCE = new SessionExpirationTimerTask();

    private static final long SESSION_TIMEOUT_NANOSECONDS = 7200_000_000_000L;

    private final List<WeakReference<SessionImpl>> registry = synchronizedList(new ArrayList<WeakReference<SessionImpl>>());

    private SessionExpirationTimerTask() {
        super();
    }

    static SessionExpirationTimerTask instance() {
        return INSTANCE;
    }

    void register(final SessionImpl session) {
        this.registry.add(new WeakReference<>(session));
    }

    @Override
    public void run() {
        final ArrayList<WeakReference<SessionImpl>> duplicatedRegistry;
        synchronized (this.registry) {
            duplicatedRegistry = new ArrayList<>(this.registry);
        }
        final long now = System.nanoTime();
        final Iterator<WeakReference<SessionImpl>> it = duplicatedRegistry.iterator();
        while (it.hasNext()) {
            final SessionImpl master = it.next().get();
            if (master == null) {
                it.remove();
                continue;
            }
            expireTimedOutSessions(now, master);
            for (final SessionImpl slave : master.getInstances()) {
                expireTimedOutSessions(now, slave);
            }
        }
    }

    // TODO very specific requirements for expiration timer (https://github.com/otrv4/otrv4/blob/master/otrv4.md#session-expiration "The session expiration timer begins at different times for the sender and the receiver of the first data message in a conversation. The sender begins their timer as they send the first data message or as they attach an encrypted message to the Non-Interactive-Auth message. The receiver begins their timer when they receive this first data message.")
    private void expireTimedOutSessions(final long now, final SessionImpl session) {
        try {
            if (now - session.getLastActivityTimestamp() > SESSION_TIMEOUT_NANOSECONDS) {
                LOGGER.log(FINE, "Expiring session " + session.getSessionID() + " (" + session.getSenderInstanceTag() + ")");
                session.expireSession();
            }
        } catch (final IncorrectStateException e) {
            LOGGER.log(FINEST, "Session instance '{0}' current state does not expire.",
                    generateIdentifier(session));
        } catch (final OtrException e) {
            LOGGER.log(WARNING, "Failure while expiring session instance " + generateIdentifier(session), e);
        }
    }
}
