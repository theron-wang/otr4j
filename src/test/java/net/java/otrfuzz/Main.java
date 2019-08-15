/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otrfuzz;

import java.net.ProtocolException;

import static net.java.otr4j.io.MessageProcessor.parseMessage;

public class Main {

    public static void main(final String[] args) throws ProtocolException {
        System.err.println(parseMessage("?OTR"));
    }
}
