/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import java.net.ProtocolException;

public final class UnknownInstanceException extends ProtocolException {

    private static final long serialVersionUID = -9038076875471875721L;

    UnknownInstanceException(final String host) {
        super(host);
    }
}
