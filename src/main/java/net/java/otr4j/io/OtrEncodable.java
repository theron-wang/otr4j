/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

/**
 * Interface indicating this type is OTR-encodable.
 */
public interface OtrEncodable {

    /**
     * OTR-encode content and write to provided OtrOutputStream.
     *
     * @param out The destination OTR output stream.
     */
    void writeTo(OtrOutputStream out);
}
