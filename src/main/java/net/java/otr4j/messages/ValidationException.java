/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.OtrException;

/**
 * Validation Exception, indicating that some part of the message failed validation.
 */
public final class ValidationException extends OtrException {

    private static final long serialVersionUID = 4750629991743759541L;

    ValidationException(final String message) {
        super(message);
    }

    ValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
