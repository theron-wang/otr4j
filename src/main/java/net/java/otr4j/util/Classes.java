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
 * Classes provides utilities that operate on the classes (types).
 */
public final class Classes {

    private Classes() {
        // No need to instantiate.
    }

    /**
     * Initialize initializes the specified classes, and expects this to succeed.
     *
     * @param classes the classes that need initialization
     * @throws IllegalStateException thrown in case initialization of a class fails.
     */
    public static void initialize(final Class<?>... classes) {
        for (final Class<?> c : classes) {
            try {
                Class.forName(c.getName());
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Failed to initialize class " + c.getName());
            }
        }
    }
}
