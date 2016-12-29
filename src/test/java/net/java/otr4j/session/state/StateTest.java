/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import org.junit.Test;

public class StateTest {

    @Test
    public void testInstantiateIncorrectStateException() {
        new State.IncorrectStateException("We're in a wrong state!");
    }
}
