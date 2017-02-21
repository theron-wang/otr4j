/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

public interface Message {

	// Unencoded message types
	int MESSAGE_ERROR = 0xff;
	int MESSAGE_QUERY = 0x100;
	int MESSAGE_PLAINTEXT = 0x102;

	// Encoded message types
	int MESSAGE_DH_COMMIT = 0x02;
	int MESSAGE_DATA = 0x03;
	int MESSAGE_DHKEY = 0x0a;
	int MESSAGE_REVEALSIG = 0x11;
	int MESSAGE_SIGNATURE = 0x12;

    /**
     * Get byte code for message type.
     *
     * This method is intended solely for use to serialize an OTR message with
     * an appropriate message type. This value should not be used to determine
     * its Java class type.
     *
     * @return Returns byte value for message type.
     */
    int getType();
}
