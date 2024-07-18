/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
/**
 * The OTRv4 interactive DAKE.
 * <p>
 * Note: this implementation of the interactive DAKE is constructed in a separate, independent state-machine. This
 * deviates from the (unfinished) OTRv4 spec, because the OTRv4 spec dictates it is part of the messaging-state. However,
 * this means that any incoming DAKE message forces the state-machine to move out of encrypted-messaging state. This is
 * not desirable, because it creates a DoS vector simply by constructing/repeating an earlier message. Extracting the
 * interactive DAKE into a separate state-machine, OTOH, follows the approach of OTRv3, which does not exhibit this
 * issue.
 * <p>
 * If we "re-transition" into encrypted-messaging state after fully completing another DAKE, it means that --
 * even if possibly unnecessary -- we transitioned after the other party has proved fully capable to performing a full
 * DAKE, thus has ownership of the client-profile.
 */
@ParametersAreNonnullByDefault
package net.java.otr4j.session.dake;

import javax.annotation.ParametersAreNonnullByDefault;