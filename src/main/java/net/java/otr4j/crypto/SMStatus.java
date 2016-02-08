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
     * Status is succeeded. SMP exchange has been fully completed and it has
     * succeeded, i.e. with positive match.
     */
    SUCCEEDED,
    /**
     * Status is failed. SMP exchange has been completed, but with negative
     * match.
     */
    FAILED;
}
