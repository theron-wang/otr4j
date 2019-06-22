/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import org.junit.Test;

public class IncorrectStateExceptionTest {

    @Test
    public void testInstantiateIncorrectStateException() {
        new IncorrectStateException("We're in a wrong state!");
    }    
}
