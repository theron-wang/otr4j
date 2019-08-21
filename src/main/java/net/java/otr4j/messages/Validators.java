/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import java.util.Date;
import java.util.Objects;

/**
 * Utilities for the benefit of shorthands when performing validations throwing {@link ValidationException}.
 */
final class Validators {

    private Validators() {
        // No need to instantiate utility class.
    }

    static <T> void validateEquals(final T object1, final T object2, final String message) throws ValidationException {
        if (Objects.equals(object1, object2)) {
            return;
        }
        throw new ValidationException(message);
    }

    static void validateExactly(final int expected, final int test, final String message) throws ValidationException {
        if (expected == test) {
            return;
        }
        throw new ValidationException(message);
    }

    static void validateAtMost(final int max, final int test, final String message) throws ValidationException {
        if (test <= max) {
            return;
        }
        throw new ValidationException(message);
    }

    static void validateDateAfter(final Date moment, final Date testDate, final String message)
            throws ValidationException {
        if (moment.before(testDate)) {
            return;
        }
        throw new ValidationException(message);
    }
}
