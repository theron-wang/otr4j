/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.util.Unit;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

/**
 * Event represents each of the possible event variants that may be signaled to the OtrEngineHost.
 *
 * @param <T> the type for the event payload
 */
public final class Event<T> {
    /**
     * An unencrypted message was received. (The message is the payload.)
     */
    public static final Event<String> UNENCRYPTED_MESSAGE_RECEIVED = new Event<>(String.class);
    /**
     * T.b.d.
     */
    // TODO change payload to include both (OTRv4) error identifier and error string
    // FIXME do we need an OTRError event, or an event that shows an error in the UI?
    public static final Event<String> ERROR = new Event<>(String.class);
    /**
     * An unreadable message was received, i.e. due to encryption keys no longer being available. (No payload.)
     */
    public static final Event<Unit> UNREADABLE_MESSAGE_RECEIVED = new Event<>(Unit.class);
    /**
     * Received message was intended for another instance. (No payload.)
     */
    public static final Event<Unit> MESSAGE_FOR_ANOTHER_INSTANCE_RECEIVED = new Event<>(Unit.class);
    /**
     * Multiple instances have been detected. (No payload.)
     */
    public static final Event<Unit> MULTIPLE_INSTANCES_DETECTED = new Event<>(Unit.class);
    // TODO first 4 bytes of TLV value are indicator (ID?) of usage, e.g. file transfer, encrypted audio, rest is freeform possibly (file)name, URL or whatever.
    /**
     * The received data message contains a TLV for use of the Extra Symmetric Key. (Payload is a composite class with
     * additional data for use of the extra symmetric key.) This event is triggered for each TLV.
     */
    public static final Event<EventExtraSymmetricKey> EXTRA_SYMMETRIC_KEY_DISCOVERED = new Event<>(EventExtraSymmetricKey.class);
    /**
     * Event is triggered if the policy forbids messaging without establishing an encrypted session first. (Payload is
     * the original message.)
     */
    public static final Event<String> ENCRYPTED_MESSAGES_REQUIRED = new Event<>(String.class);
    /**
     * Session is `Finished`, indicating that the user should manually transition back to plaintext to indicate they
     * are aware that messages are no longer sent confidentially. (No payload.)
     */
    // TODO should event type include a copy of the message sent in SessionFinished? (or just show error?)
    public static final Event<Unit> SESSION_FINISHED = new Event<>(Unit.class);
    /**
     * Signal Engine Host to ask user for answer to the question provided by the
     * other party in the SMP authentication session. (Payload is the question (SMP1Q) or empty string if initiated
     * without accompanying question (SMP1).)
     */
    public static final Event<String> SMP_REQUEST_SECRET = new Event<>(String.class);
    /**
     * When a remote user's key is verified via the Socialist Millionaire's Protocol (SMP) shared passphrase or
     * question/answer, this event will be called upon successful completion of that process.
     * (Payload is the fingerprint that is verified.)
     */
    public static final Event<String> SMP_SUCCEEDED = new Event<>(String.class);

    /**
     * If the Socialist Millionaire's Protocol (SMP) process fails, then this event signals the fingerprint that should
     * be marked as untrustworthy. (Payload is the fingerprint.)
     */
    public static final Event<String> SMP_FAILED = new Event<>(String.class);
    /**
     * Signal OTR Engine Host to inform that SMP is aborted.
     * <p>
     * Payload is a boolean value that indicates whether: `false` abort is called by user request or incoming abort TLV,
     * or `true` abort is motivated by cheating.
     */
    public static final Event<EventAbortReason> SMP_ABORTED = new Event<>(EventAbortReason.class);

    private final Class<T> type;

    private Event(final Class<T> type) {
        this.type = requireNonNull(type);
    }

    /**
     * Convert the (presumably untyped) payload to type corresponding to the event.
     *
     * @param payload the (presumably untyped) payload
     * @return Returns the payload cast to the appropriate type.
     */
    @CheckReturnValue
    @Nonnull
    public T convert(final Object payload) {
        return this.type.cast(payload);
    }
}
