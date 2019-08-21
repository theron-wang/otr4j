/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.smpv4;

final class SMPAbortException extends Exception {

    private static final long serialVersionUID = 3561843234075404537L;

    SMPAbortException(final String message) {
        super(message);
    }
}
