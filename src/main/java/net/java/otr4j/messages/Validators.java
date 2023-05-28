/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import java.time.Instant;
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

    static <T> void validateNotEquals(final T object1, final T object2, final String message) throws ValidationException {
        if (Objects.equals(object1, object2)) {
            throw new ValidationException(message);
        }
    }

    // FIXME needs testing
    static <T> void validateNotEquals(final T o1, final T o2, final T o3, final T o4, final String message)
            throws ValidationException {
        if (Objects.equals(o1, o2) || Objects.equals(o1, o3) || Objects.equals(o1, o4) || Objects.equals(o2, o3)
                || Objects.equals(o2, o4) || Objects.equals(o3, o4)) {
            throw new ValidationException(message);
        }
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

    static void validateDateAfter(final Instant moment, final Instant testDate, final String message)
            throws ValidationException {
        if (moment.isBefore(testDate)) {
            return;
        }
        throw new ValidationException(message);
    }
}
