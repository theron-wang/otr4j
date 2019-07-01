/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import org.junit.Test;

import static net.java.otr4j.util.Objects.requireEquals;
import static net.java.otr4j.util.Objects.requireNotEquals;

@SuppressWarnings("ConstantConditions")
public final class ObjectsTest {

    @Test(expected = NullPointerException.class)
    public void testRequireNotEqualsFirstNull() {
        requireNotEquals(null, new Object(), "Good.");
    }

    @Test(expected = NullPointerException.class)
    public void testRequireNotEqualsSecondNull() {
        requireNotEquals(new Object(), null, "Good.");
    }

    @Test(expected = NullPointerException.class)
    public void testRequireNotEqualsNulls() {
        requireNotEquals(null, null, "Good.");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireNotEqualsEqual() {
        final Object o = new Object();
        requireNotEquals(o, o, "Good.");
    }

    @Test
    public void testRequireNotEqualsNotEqual() {
        requireNotEquals(new Object(), new Object(), "Good.");
    }

    @Test(expected = NullPointerException.class)
    public void testRequireEqualsNulls() {
        requireEquals(null, null, "Not good.");
    }

    @Test(expected = NullPointerException.class)
    public void testRequireEqualsFirstNull() {
        requireEquals(null, new Object(), "Not good.");
    }

    @Test(expected = NullPointerException.class)
    public void testRequireEqualsSecondNull() {
        requireEquals(new Object(), null, "Not good.");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireEqualsDifferent() {
        requireEquals(new Object(), new Object(), "Good.");
    }

    @Test
    public void testRequireEqualsEqual() {
        final Object o = new Object();
        requireEquals(o, o, "Not good.");
    }
}