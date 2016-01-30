/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

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
}
