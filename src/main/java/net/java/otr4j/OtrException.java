/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

// TODO consider making OtrException abstract and have individual packages define exceptions based on OtrException.
public class OtrException extends Exception {

    private static final long serialVersionUID = -6327624437614707245L;

    public OtrException(final Throwable e) {
        super(e);
    }

    public OtrException(final String message) {
        super(message);
    }

    public OtrException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
