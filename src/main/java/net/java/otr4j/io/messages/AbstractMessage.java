/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

import javax.annotation.Nonnull;

/**
 * 
 * @author George Politis
 */
public abstract class AbstractMessage {
    // TODO as a long-term goal it would be nice if we could deprecate the messageType field in favor of leveraging the class hierarchy for this. At this moment, there is a valid risk that we pass on an invalid message type value and thus cast incorrectly. We do not have this risk if we use the class hierarchy to determine the message type.

	// Fields.
	public final int messageType;

	// Ctor.
	public AbstractMessage(final int messageType) {
		this.messageType = messageType;
	}

	// Methods.
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + messageType;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
            return true;
        }
		if (obj == null) {
            return false;
        }
		if (getClass() != obj.getClass()) {
            return false;
        }
		AbstractMessage other = (AbstractMessage) obj;
		if (messageType != other.messageType) {
            return false;
        }
		return true;
	}

	// Unencoded
	public static final int MESSAGE_ERROR = 0xff;
	public static final int MESSAGE_QUERY = 0x100;
	public static final int MESSAGE_PLAINTEXT = 0x102;

    /**
     * Check if message m is an instance of specified type before casting. In
     * case type mismatches, throw IllegalArgumentException. This method is
     * intended to run after deciding on which type to cast to using the
     * AbstractMessage's 'messageType' field.
     *
     * NOTE that this is clearly a work-around solution to doing safe casting,
     * because we currently determine type by the 'messageType' field. Which is
     * a form of "safety through convention". As Java supports type hierarchies,
     * we can already determine message type through instance-of checks. This
     * should be changed at some point, but this solution better fits the
     * current code base.
     *
     * @param <T> The target type.
     * @param clazz The target type as an object.
     * @param m The message that needs to be cast.
     * @return Returns message casted in specified type if correct. Throws
     * IllegalArgumentException if message type does not match.
     */
    @Nonnull
    public static final <T extends AbstractMessage> T checkCast(@Nonnull final Class<T> clazz, @Nonnull final AbstractMessage m) {
        if (!clazz.isInstance(m)) {
            throw new IllegalArgumentException("Mismatch in 'messageType' value vs actual message type: we expected to cast message of type " + m.getClass().getCanonicalName() + " to " + clazz.getCanonicalName() + ", but it isn't.");
        }
        return (T) m;
    }
}
