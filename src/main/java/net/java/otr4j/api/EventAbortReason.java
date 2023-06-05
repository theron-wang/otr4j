/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

/**
 * EventAbortReason is the set of reasons for aborting the SMP.
 */
public enum EventAbortReason {
    /**
     * User-initiated abort, either by the local user or the remote user (through TLV).
     */
    USER,
    /**
     * SMP process interrupted by unexpected event, e.g. reset for not following protocol. Not necessarily malicious.
     */
    INTERRUPTION,
    /**
     * SMP process reset because of some violation, such as bad input or conclusion 'cheated'.
     */
    VIOLATION
}
