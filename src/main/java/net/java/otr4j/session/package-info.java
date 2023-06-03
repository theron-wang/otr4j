/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
/**
 * otr4j session management.
 */
@ParametersAreNonnullByDefault
package net.java.otr4j.session;
// TODO what to do with queued messages given that multiple sessions might be established in short timespan if multiple clients are active. (drain to first session, may result in sending to an inactive client instead of intended client if multiple clients connected) (//  * What to do with queued messages? The obvious answer is: send them as soon as a private session has been established. However, in practice it isn't that simple. A session can be established with multiple clients at a time. Do we send the queued messages to the first established session instance? Or to all instances? If only to one instance, there is a risk that we send it to the wrong instance. That is, a client is on and happens to be first in establishing the connection, but it isn't the client that the user is currently working on. Then there is a risk of exposing information to the wrong computer.)

import javax.annotation.ParametersAreNonnullByDefault;