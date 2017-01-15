/**
 * Package containing otr message types.
 */
// TODO consider making fields private and forcing user code to go through accessor methods. (will break API)
// TODO define interface for serializable messages.
// TODO define messages that are unencrypted variations on existing encrypted messages, that are not serializable.
// TODO should we use some other byte-array verification function that is constant-time (or near constant-time)? (Probably not such a big deal.)
package net.java.otr4j.io.messages;
