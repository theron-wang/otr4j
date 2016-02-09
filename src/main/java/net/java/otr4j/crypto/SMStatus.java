package net.java.otr4j.crypto;

/**
 * Enum of SM statuses.
 *
 * @author Danny van Heumen
 */
public enum SMStatus {
    /**
     * Status is undecided. No SMP exchange has started, or SMP exchange has
     * started but not completed yet.
     */
    UNDECIDED,
    /**
     * SMP exchange is in progress.
     */
    INPROGRESS,
    /**
     * SMP exchange final state for normal cases. SMP exchange has been fully
     * completed and it has succeeded, i.e. with positive outcome.
     */
    SUCCEEDED,
    /**
     * SMP exchange final state for normal cases. SMP exchange has been
     * completed, but with negative outcome.
     */
    FAILED,
    /**
     * SMP exchange final state for exceptional cases. This might indicate that
     * invalid message were sent on purpose to play the protocol and as a
     * consequence processing did not finish as expected.
     */
    CHEATED;
}
