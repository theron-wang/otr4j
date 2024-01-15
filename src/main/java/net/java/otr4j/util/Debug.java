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
 * Debug utils for accessing and/or printing information for debugging purposes.
 */
// TODO no use of `Debug` should remain once things are working.
@SuppressWarnings({"SystemOut", "PMD.SystemPrintln"})
public final class Debug {

    private Debug() {
        // No need to instantiate.
    }

    /**
     * Dump a byte-array as a hexadecimal value (0xVALUE).
     *
     * @param label the label for the value-dump to make multiple dumps identifiable.
     * @param bytes the value(array)
     */
    public static void dumpHex(final String label, final byte[] bytes) {
        System.err.print(label + "(" + bytes.length + "): 0x");
        for (final byte b : bytes) {
            System.err.printf("%02x", b);
        }
        System.err.println();
    }
}
