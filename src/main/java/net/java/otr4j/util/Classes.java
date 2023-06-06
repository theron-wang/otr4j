/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import java.lang.reflect.Field;

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
            } catch (final ClassNotFoundException e) {
                throw new IllegalStateException("Failed to initialize class " + c.getName(), e);
            }
        }
    }

    /**
     * Read value from class field.
     *
     * @param type the type of value
     * @param entry the instance that is the entrypoint to the inspection
     * @param fieldNames the field names of consecutive (intermediate) field names
     * @return Returns the value in the field.
     * @param <T> the type of the intended field's value
     */
    public static <T> T readField(final Class<T> type, final Object entry, final String... fieldNames) {
        Object value = entry;
        for (final String name : fieldNames) {
            value = readField(value, name);
        }
        return type.cast(value);
    }

    /**
     * Read value from class field.
     *
     * @param type the type of value
     * @param entry the instance that is the entrypoint to the inspection
     * @param fieldName the field names of consecutive (intermediate) field names
     * @return Returns the value in the field.
     * @param <T> the type of the intended field's value
     */
    public static <T> T readField(final Class<T> type, final Object entry, final String fieldName) {
        return type.cast(readField(entry, fieldName));
    }

    /**
     * Read (untyped) value from class field.
     *
     * @param entry the instance for inspection
     * @param fieldName the field name
     * @return Returns the value in the field.
     */
    @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
    public static Object readField(final Object entry, final String fieldName) {
        try {
            final Field field = entry.getClass().getDeclaredField(fieldName);
            final boolean accessible = field.canAccess(entry);
            if (!accessible) {
                field.setAccessible(true);
            }
            final Object value = field.get(entry);
            if (!accessible) {
                field.setAccessible(false);
            }
            return value;
        } catch (final NoSuchFieldException | IllegalAccessException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
