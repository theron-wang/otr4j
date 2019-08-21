/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
/**
 * Package containing the Messaging states defined by OTR.
 */
@ParametersAreNonnullByDefault
package net.java.otr4j.session.state;
// TODO review clearing of sensitive data for other than expected transition paths for states.
// FIXME review state machine (allowed) transitions now that DAKE is in. (OTRv3 state transitions still to do.) (https://github.com/otrv4/otrv4/commit/9427dedf5c09cd9d0cd6ef1e2580a76ad694149f)
// FIXME spec says "Picks a compatible version of OTR listed on Alice's profile, and follows the specification for this version." --> review if this changes anything for the current control logic. (This seems to be for the future only, as we shouldn't pick OTRv3 if a ClientProfile is sent -- spec says version 4 must be present in profile.)

import javax.annotation.ParametersAreNonnullByDefault;