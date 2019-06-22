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

import static net.java.otr4j.util.Strings.join;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class StringsTest {

    @Test(expected = NullPointerException.class)
    public void testJoinNull() {
        join((String[]) null);
    }

    @Test
    public void testJoinZeroStrings() {
        assertEquals("", join());
    }

    @Test
    public void testJoinSingleString() {
        assertEquals("Hello world", join("Hello world"));
    }

    @Test
    public void testJoinTwoStrings() {
        assertEquals("HelloWorld", join("Hello", "World"));
    }

    @Test
    public void testJoinManyStrings() {
        assertEquals("HelloWorldThisIsJohnDo", join("Hello", "World", "This", "Is", "John", "Do"));
    }

    @Test
    public void testJoiningManyEmptyStrings() {
        assertEquals("", join("", "", "", ""));
    }
}
