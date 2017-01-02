/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.logging.Logger;

/**
 * OtrPolicy is an intelligent policy class that will return the current
 * policy's setting on various aspects. The policy object is intelligent enough
 * to adjust its answer to its composition. For example, if all OTR protocol
 * versions are denied, it will not return true to sending whitespace tags or
 * (re)starting AKE.
 *
 * @author George Politis
 */
// FIXME make class final
public class OtrPolicy {

    private static final Logger LOGGER = Logger.getLogger(OtrPolicy.class.getCanonicalName());

    /**
     * Flag for indicating otr V1 is allowed in this policy.
     *
     * @deprecated OTR v1 is no longer supported.
     */
    @Deprecated
    public static final int ALLOW_V1 = 0x01;

    public static final int ALLOW_V2 = 0x02;
    // ALLOW_V3 is set to 0x40 for compatibility with older versions
    public static final int ALLOW_V3 = 0x40;
    public static final int REQUIRE_ENCRYPTION = 0x04;
    public static final int SEND_WHITESPACE_TAG = 0x8;
    public static final int WHITESPACE_START_AKE = 0x10;
    public static final int ERROR_START_AKE = 0x20;
    public static final int VERSION_MASK = (ALLOW_V2 | ALLOW_V3);

    // The four old version 1 policies correspond to the following combinations
    // of flags (adding an allowance for version 2 of the protocol):

    public static final int NEVER = 0x00;
    public static final int OPPORTUNISTIC = (ALLOW_V2 | ALLOW_V3
            | SEND_WHITESPACE_TAG | WHITESPACE_START_AKE | ERROR_START_AKE);
    public static final int OTRL_POLICY_MANUAL = (ALLOW_V2 | ALLOW_V3);
    public static final int OTRL_POLICY_ALWAYS = (ALLOW_V2 | ALLOW_V3
            | REQUIRE_ENCRYPTION | WHITESPACE_START_AKE | ERROR_START_AKE);
    public static final int OTRL_POLICY_DEFAULT = OPPORTUNISTIC;

    public OtrPolicy() {
        this(NEVER);
    }

    public OtrPolicy(final int policy) {
        this.policy = policy;
    }

    private int policy;

    /**
     * Get full policy value. Returns raw policy value containing composition of
     * bit flags.
     *
     * @return Returns the raw policy value.
     */
    public int getPolicy() {
        return policy;
    }

    /**
     * getAllowV1 is deprecated as OTR V1 is not supported anymore.
     *
     * @return Always returns false.
     * @deprecated OTR V1 is not supported anymore.
     */
    @Deprecated
    public boolean getAllowV1() {
        return false;
    }

    /**
     * Get OTR v2 policy.
     *
     * @return Returns true if OTR version 2 is allowed.
     */
    public boolean getAllowV2() {
        return (policy & OtrPolicy.ALLOW_V2) != 0;
    }

    /**
     * Get OTR v3 policy.
     *
     * @return Returns true if OTR version 3 is allowed.
     */
    public boolean getAllowV3() {
        return (policy & OtrPolicy.ALLOW_V3) != 0;
    }

    /**
     * Policy regarding restarting AKE upon receiving an OTR Error message.
     *
     * The answer depends on whether at least one protocol version is enabled.
     * If all versions are denied, we will return false.
     *
     * @return Returns true if intention is to re-establish OTR encrypted
     * session immediately after receiving an error message. Returns false if
     * policy is set to false, or if no OTR protocol version is allowed.
     */
    public boolean getErrorStartAKE() {
        if (!viable()) {
            LOGGER.warning("Returning false to getErrorStartAKE as no OTR protocol version is allowed.");
            return false;
        }
        return (policy & OtrPolicy.ERROR_START_AKE) != 0;
    }

    /**
     * Require encryption to be used.
     *
     * @return Returns true if encryption needs to be used for any
     * communication, or false if message are allowed to be sent unencrypted in
     * case an OTR session is not established.
     */
    public boolean getRequireEncryption() {
        return (policy & OtrPolicy.REQUIRE_ENCRYPTION) != 0;
    }

    /**
     * Policy regarding automatically sending whitespace tag.
     *
     * The answer depends on whether at least one protocol version is enabled.
     * If all versions are denied, we will return false.
     *
     * @return Returns true if policy is set to send whitespace tags and at
     * least one OTR protocol version is allowed. Returns false if policy is set
     * to false, or if no OTR protocol version is allowed.
     */
    public boolean getSendWhitespaceTag() {
        if (!viable()) {
            LOGGER.warning("Returning false to getSendWhitespaceTag as no OTR protocol version is allowed.");
            return false;
        }
        return (policy & OtrPolicy.SEND_WHITESPACE_TAG) != 0;
    }

    /**
     * Policy regarding automatically initiating OTR encrypted session upon
     * receiving whitespace tag.
     *
     * The answer depends on whether at least one protocol version is enabled.
     * If all versions are denied, we will return false.
     *
     * @return Returns true if policy is set to initiate OTR encrypted session
     * and at least one OTR protocol version is allowed. Returns false if policy
     * is set to false, or if no OTR protocol version is allowed.
     */
    public boolean getWhitespaceStartAKE() {
        if (!viable()) {
            LOGGER.warning("Returning false to getWhitespaceStartAKE as no OTR protocol version is allowed.");
            return false;
        }
        return (policy & OtrPolicy.WHITESPACE_START_AKE) != 0;
    }

    /**
     * OTR V1 is not supported anymore. Calling this method will not change the
     * policy.
     *
     * @param value
     * @deprecated Support for OTR V1 is dropped.
     */
    @Deprecated
    public void setAllowV1(final boolean value) {
    }

    public void setAllowV2(final boolean value) {
        if (value) {
            policy |= ALLOW_V2;
        } else {
            policy &= ~ALLOW_V2;
        }
    }

    public void setAllowV3(final boolean value) {
        if (value) {
            policy |= ALLOW_V3;
        } else {
            policy &= ~ALLOW_V3;
        }
    }

    public void setErrorStartAKE(final boolean value) {
        if (value) {
            policy |= ERROR_START_AKE;
        } else {
            policy &= ~ERROR_START_AKE;
        }
    }

    public void setRequireEncryption(final boolean value) {
        if (value) {
            policy |= REQUIRE_ENCRYPTION;
        } else {
            policy &= ~REQUIRE_ENCRYPTION;
        }
    }

    public void setSendWhitespaceTag(final boolean value) {
        if (value) {
            policy |= SEND_WHITESPACE_TAG;
        } else {
            policy &= ~SEND_WHITESPACE_TAG;
        }
    }

    public void setWhitespaceStartAKE(final boolean value) {
        if (value) {
            policy |= WHITESPACE_START_AKE;
        } else {
            policy &= ~WHITESPACE_START_AKE;
        }
    }

    public boolean getEnableAlways() {
        return getEnableManual() && getErrorStartAKE()
                && getRequireEncryption() && getWhitespaceStartAKE();
    }

    /**
     * Set EnableAlways policy configuration.
     *
     * WARNING: You should use this method only to enable the policy. If you
     * provide false to this it will also disable ErrorStartAKE,
     * WhitespaceStartAKE and RequireEncryption. This might not be the behavior
     * you would expect.
     *
     * @param value 'true' to enable EnableAlways policy.
     */
    // TODO modify this method such that 'false' does not start disabling arbitrary OTR policy features. This behavior simply doesn't make sense.
    public void setEnableAlways(final boolean value) {
        if (value) {
            setEnableManual(true);
        }

        setErrorStartAKE(value);
        setRequireEncryption(value);
        setWhitespaceStartAKE(value);
    }

    public boolean getEnableManual() {
        return getAllowV2() && getAllowV3();
    }

    // TODO modify this method such that 'false' does not disable all supported protocols. The 'EnableManual' policy defines OTR's behavior for manually starting an OTR session, but it does not make sense to just disable all protocols if you do not want this behavior.
    public void setEnableManual(final boolean value) {
        setAllowV2(value);
        setAllowV3(value);
    }

    /**
     * Check if the current policy is viable for starting OTR encrypted
     * sessions given the restrictions in the policy.
     *
     * @return Returns true if any supported OTR protocol version is enabled and
     * therefore we can set up an encrypted session with a client with
     * compatible policy. Returns false if no protocol version is enabled.
     */
    public boolean viable() {
        return getAllowV2() || getAllowV3();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || obj.getClass() != this.getClass()) {
            return false;
        }

        OtrPolicy policy = (OtrPolicy) obj;

        return policy.policy == this.policy;
    }

    @Override
    public int hashCode() {
        return this.policy;
    }
}
