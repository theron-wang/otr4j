/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import javax.annotation.Nonnull;

/**
 * String utilities.
 */
public final class Strings {

    private Strings() {
        // No need to instantiate utility class.
    }

    /**
     * Join multiple String parts into a single concatenated String.
     *
     * @param parts separated string parts
     * @return Joint string.
     */
    @Nonnull
    public static String join(final String... parts) {
        final StringBuilder builder = new StringBuilder();
        for (final String part : parts) {
            builder.append(part);
        }
        return builder.toString();
    }
}
