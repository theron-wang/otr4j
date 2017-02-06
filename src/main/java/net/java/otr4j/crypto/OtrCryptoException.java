/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.crypto;

import net.java.otr4j.OtrException;

/**
 * Exception for issues w.r.t. crypto operations in otr4j.
 */
public final class OtrCryptoException extends OtrException {

    private static final long serialVersionUID = -2636945817636034632L;

    public OtrCryptoException(final String message) {
        super(message);
    }

    public OtrCryptoException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public OtrCryptoException(final Throwable e) {
        super(e);
    }
}
