/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.io.OtrOutputStream;

import static java.util.Objects.requireNonNull;

final class SMPMessage4 implements SMPMessage {

    final Point rb;

    final Scalar cr;

    final Scalar d7;

    SMPMessage4(final Point rb, final Scalar cr, final Scalar d7) {
        this.rb = requireNonNull(rb);
        this.cr = requireNonNull(cr);
        this.d7 = requireNonNull(d7);
    }

    @Override
    public void writeTo(final OtrOutputStream out) {
        out.writePoint(this.rb).writeScalar(this.cr).writeScalar(this.d7);
    }
}
