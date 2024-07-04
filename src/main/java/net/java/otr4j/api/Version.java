/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import javax.annotation.Nullable;
import java.util.EnumSet;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Versions of the protocol that the code-base is aware of.
 */
public enum Version {
    /**
     * NONE, the indicator in case no protocol version is applicable.
     */
    NONE(0),
    /**
     * Protocol version 1.
     */
    ONE(1),
    /**
     * Protocol version 2.
     */
    TWO(2),
    /**
     * Protocol version 3.
     */
    THREE(3),
    /**
     * Protocol version 4.
     */
    FOUR(4);

    private static final Logger LOGGER = Logger.getLogger(Version.class.getName());

    /**
     * Supported protocol versions.
     */
    public static final EnumSet<Version> SUPPORTED = EnumSet.of(TWO, THREE, FOUR);

    /**
     * The value that represents this protocol version.
     */
    public final int value;

    Version(final int value) {
        this.value = value;
    }

    /**
     * Match any protocol version on the corresponding ordinal, also the integer value for the protocol version.
     *
     * @param version protocol version
     * @return Returns the version instance corresponding to the integer value for the version.
     */
    @Nullable
    public static Version match(final int version) {
        for (final Version v : values()) {
            if (v.value == version) {
                return v;
            }
        }
        LOGGER.log(Level.FINEST, "Cannot find version match for value {0}", new Object[]{version});
        return null;
    }
}
