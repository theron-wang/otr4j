/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import net.java.otr4j.api.Version;
import net.java.otr4j.io.Fragment;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.MessageProcessor;

import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Random;
import java.util.concurrent.BlockingQueue;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Arrays.contains;

public final class BlockingQueuesTestUtils {

    public static void rearrangeFragments(final BlockingQueue<String> queue, final Random random)
            throws ProtocolException {
        shuffle(queue, random);
        reorderOTRv3Fragments(queue);
    }

    public static <T> void drop(final int[] drops, final BlockingQueue<T> queue) {
        java.util.Arrays.sort(drops);
        final ArrayList<T> list = new ArrayList<>();
        queue.drainTo(list);
        for (int i = 0; i < list.size(); i++) {
            if (contains(i, drops)) {
                continue;
            }
            queue.add(list.get(i));
        }
    }

    /**
     * Shuffle the contents of the provided blocking queue.
     *
     * @param queue  the blocking queue
     * @param random the Random instance (allows deterministic random for reproducible testing)
     * @param <T>    the type of the content in the blocking queue
     */
    public static <T> void shuffle(final BlockingQueue<T> queue, final Random random) {
        final ArrayList<T> list = new ArrayList<>();
        queue.drainTo(list);
        java.util.Collections.shuffle(list, random);
        queue.addAll(list);
    }

    public static void reorderOTRv3Fragments(final BlockingQueue<String> queue) throws ProtocolException {
        final ArrayList<String> messages = new ArrayList<>();
        queue.drainTo(messages);
        final ArrayList<FragmentEntry> fragments = new ArrayList<>();
        for (int i = 0; i < messages.size(); i++) {
            final String msg = messages.get(i);
            final Message m = MessageProcessor.parseMessage(msg);
            if (m instanceof Fragment && ((Fragment) m).getVersion() == Version.THREE) {
                fragments.add(new FragmentEntry(i, ((Fragment) m).getIndex(), msg));
            }
        }
        fragments.sort(Comparator.comparingInt(o -> o.index));
        int nextFragment = 0;
        for (int i = 0; i < messages.size(); i++) {
            if (containsFragment(fragments, i)) {
                messages.set(i, fragments.get(nextFragment).raw);
                nextFragment++;
            }
        }
        queue.addAll(messages);
    }

    private static boolean containsFragment(final Iterable<FragmentEntry> entries, final int position) {
        for (final FragmentEntry entry : entries) {
            if (entry.position == position) {
                return true;
            }
        }
        return false;
    }

    private static final class FragmentEntry {

        private final int position;
        private final int index;
        private final String raw;

        private FragmentEntry(final int position, final int index, final String raw) {
            this.position = position;
            this.index = index;
            this.raw = requireNonNull(raw);
        }
    }
}
