/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

import java.util.Set;

/**
 * 
 * @author George Politis
 */
public class QueryMessage extends AbstractMessage {
	// Fields.
	public final Set<Integer> versions;

	// Ctor.
	public QueryMessage(final Set<Integer> versions) {
		this(MESSAGE_QUERY, versions);
	}

    protected QueryMessage(final int messageType, final Set<Integer> versions) {
		super(messageType);
		this.versions = versions;
	}

	// Methods.
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result
				+ ((versions == null) ? 0 : versions.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
            return true;
        }
		if (!super.equals(obj)) {
            return false;
        }
		if (getClass() != obj.getClass()) {
            return false;
        }
		QueryMessage other = (QueryMessage) obj;
		if (versions == null) {
			if (other.versions != null) {
                return false;
            }
		} else if (!versions.equals(other.versions)) {
            return false;
        }
		return true;
	}

}
