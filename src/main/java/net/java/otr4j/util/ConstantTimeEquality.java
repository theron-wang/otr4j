/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import com.google.errorprone.annotations.CheckReturnValue;

/**
 * Interface to define constant-time equality method.
 *
 * @param <T> The type of the other instance in the constant-time equality check.
 */
public interface ConstantTimeEquality<T> {

    /**
     * Constant-time equals. The execution time is always the same irrespective of whether or not the instances are
     * equal.
     *
     * The generic type ensures that we are comparing suitable types. The implementation should NOT return early when
     * the same instance is encountered, as we cannot know for sure whether or not same instance is an expected case.
     *
     * @param o other instance
     * @return Returns true iff equal, or false otherwise.
     */
    @CheckReturnValue
    boolean constantTimeEquals(T o);
}
