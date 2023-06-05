/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

/**
 * A trivial type Unit, which cannot be instantiated and offers only a single instance to work with.
 * <p>
 * This is similar to java.lang.Void, except that Void requires null as argument, as it is not possible to acquire an
 * instance.
 */
@SuppressWarnings({"InstantiationOfUtilityClass", "PMD.AvoidFieldNameMatchingTypeName"})
public final class Unit {
    /**
     * The single instance of Unit available.
     */
    public static final Unit UNIT = new Unit();

    private Unit() {
        // Cannot instantiate this class.
    }
}

