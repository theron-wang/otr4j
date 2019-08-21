/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.Nonnull;
import java.math.BigInteger;

public final class PointTestUtils {

    /**
     * Construct a new point based on scalar values for x and y coordinates.
     *
     * @param x the x-coordinate
     * @param y the y-coordinate
     * @return Returns newly created point.
     */
    @Nonnull
    public static Point createPoint(final BigInteger x, final BigInteger y) {
        return new Point(Points.createPoint(x, y).encode());
    }
}
