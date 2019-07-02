/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;

/**
 * Checked exception that is thrown for cases where the method call is not appropriate. Given the nature of the
 * protocol, state changes may happen at any time. The nature of the checked exception can be used to handle unexpected
 * state transitions appropriately.
 */
public final class IncorrectStateException extends OtrException {

    private static final long serialVersionUID = -5335635776510194254L;

    IncorrectStateException(final String message) {
        super(message);
    }
}
