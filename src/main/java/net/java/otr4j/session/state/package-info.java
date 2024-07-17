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
// TODO spec says "Picks a compatible version of OTR listed on Alice's profile, and follows the specification for this version." --> review if this changes anything for the current control logic. (This seems to be for the future only, as we shouldn't pick OTRv3 if a ClientProfile is sent -- spec says version 4 must be present in profile.)
// TODO move Interactive DAKE into an independent state machine. The spec doesn't account for DAKE interactions while an encrypted session is active. With session and DAKE being one state-machine, this would necessitate ending an encrypted session before the DAKE has run to completion. (StateInitial, StateAwaitingAuthR and StateAwaitingAuthI)
import javax.annotation.ParametersAreNonnullByDefault;