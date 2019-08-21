/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import static java.util.Objects.requireNonNull;

/**
 * Additional utilities for Objects.
 */
public final class Objects {

    private Objects() {
        // No need to instantiate utility class.
    }

    /**
     * Require two objects to be equal.
     *
     * @param o1      instance 1
     * @param o2      instance 2
     * @param message the error message in case they are not equal, violating the requirement.
     * @param <T>     The expected type of the objects, such that syntactic type verification can be performed.
     */
    public static <T> void requireEquals(final T o1, final T o2, final String message) {
        if (java.util.Objects.equals(requireNonNull(o1), requireNonNull(o2))) {
            return;
        }
        throw new IllegalArgumentException(message);
    }

    /**
     * Require two objects to not be equal.
     * <p>
     * Throws an IllegalArgumentException in case requirement is violated.
     *
     * @param o1      instance 1
     * @param o2      instance 2
     * @param message the error message in case they are equal, violating the requirement.
     * @param <T>     The expected type of the objects, such that syntactic type verification can be performed.
     */
    public static <T> void requireNotEquals(final T o1, final T o2, final String message) {
        if (java.util.Objects.equals(requireNonNull(o1), requireNonNull(o2))) {
            throw new IllegalArgumentException(message);
        }
    }
}
