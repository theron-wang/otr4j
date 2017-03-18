
package net.java.otr4j.test.dummyclient;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.*;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.session.*;

/**
 * Created by gp on 2/5/14.
 */
public class DummyClient {

    private Logger logger;
	private final String account;
	private Session session;
	private OtrPolicy policy;
	private Connection connection;
	private MessageProcessor processor;
	private final Queue<ProcessedTestMessage> processedMsgs = new LinkedList<>();
	private final HashMap<SessionID, String> smpQuestions = new HashMap<>();

    private CountDownLatch lock;
    private int verified = NOTSET;
    public static final int NOTSET = 0;
    public static final int UNVERIFIED = 1;
    public static final int VERIFIED = 2;

    public static DummyClient[] getConversation() {
        DummyClient bob = new DummyClient("Bob@Wonderland");
        bob.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                | OtrPolicy.ERROR_START_AKE));

        DummyClient alice = new DummyClient("Alice@Wonderland");
        alice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2
                | OtrPolicy.ALLOW_V3 | OtrPolicy.ERROR_START_AKE));

        Server server = new PriorityServer();
        alice.connect(server);
        bob.connect(server);
        return new DummyClient[] { alice, bob };
    }

    public static DummyClient[] getConversation(CountDownLatch aliceLock, CountDownLatch bobLock) {
		DummyClient bob = new DummyClient("Bob@Wonderland", bobLock);
		bob.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland", aliceLock);
		alice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2
				| OtrPolicy.ALLOW_V3 | OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob.connect(server);
		return new DummyClient[] { alice, bob };
	}

	public static boolean forceStartOtr(DummyClient alice, DummyClient bob)
			throws OtrException {
		bob.secureSession(alice.getAccount());

		alice.pollReceivedMessage(); // Query
		bob.pollReceivedMessage(); // DH-Commit
		alice.pollReceivedMessage(); // DH-Key
		bob.pollReceivedMessage(); // Reveal signature
		alice.pollReceivedMessage(); // Signature

		return bob.getSession().getSessionStatus() == SessionStatus.ENCRYPTED
				&& alice.getSession().getSessionStatus() == SessionStatus.ENCRYPTED;
	}

	public DummyClient(String account) {
	    this(account, null);
	}

	private DummyClient(String account, CountDownLatch lock) {
	    this.lock = lock;
	    logger = Logger.getLogger(account);
		this.account = account;
	}

	public Session getSession() {
		return session;
	}

	public String getAccount() {
		return account;
	}

	public int getVerified() {
	    return verified;
	}

	public void setPolicy(OtrPolicy policy) {
		this.policy = policy;
	}

    public void init(String recipient, String message) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = OtrSessionManager.createSession(sessionID, new DummyOtrEngineHostImpl());
		}
        session.startSession();
    }

	public void send(@Nonnull String recipient, @Nonnull String s) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = OtrSessionManager.createSession(sessionID, new DummyOtrEngineHostImpl());
		}
		String[] outgoingMessage = session.transformSending(s, Collections.<TLV>emptyList());
		for (String part : outgoingMessage) {
			connection.send(recipient, part);
		}
	}

	public void exit() throws OtrException {
		this.processor.stop();
		if (session != null)
			session.endSession();
	}

	public void receive(String sender, String s) throws OtrException {
		this.processor.enqueue(sender, s);
	}

	public void connect(Server server) {
		this.processor = new MessageProcessor();
		new Thread(this.processor).start();
		this.connection = server.connect(this);
	}

    public void stop() {
        this.processor.stop();
    }

    public void stopBeforeProcessingNextMessage() {
        this.processor.stopBeforeProcessingNextMessage();
    }

    public TestMessage getNextTestMessage() {
        return this.processor.getNextTestMessage();
    }

	public void secureSession(String recipient) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = OtrSessionManager.createSession(sessionID, new DummyOtrEngineHostImpl());
		}

		session.startSession();
	}

	public Connection getConnection() {
		return connection;
	}

	public String getSmpQuestion(SessionID sessionId) {
	    return smpQuestions.get(sessionId);
	}

	public ProcessedTestMessage pollReceivedMessage() {
		synchronized (processedMsgs) {
			ProcessedTestMessage m;
			while ((m = processedMsgs.poll()) == null) {
                logger.finest("polling");
				try {
					processedMsgs.wait();
				} catch (InterruptedException e) {
                    e.printStackTrace();
				}
			}

			return m;
		}
	}

	class MessageProcessor implements Runnable {
		private final Queue<TestMessage> messageQueue = new LinkedList<TestMessage>();
		private boolean stopped;
        private boolean stopBeforeProcessingNextMessage;
        private TestMessage m;

		private void process(TestMessage m) throws OtrException {
			if (session == null) {
				final SessionID sessionID = new SessionID(account, m.getSender(), "DummyProtocol");
				session = OtrSessionManager.createSession(sessionID, new DummyOtrEngineHostImpl());
			}

			String receivedMessage = session.transformReceiving(m.getContent());
			synchronized (processedMsgs) {
				processedMsgs.add(new ProcessedTestMessage(m, receivedMessage));
				processedMsgs.notifyAll();
			}
		}

		public void run() {
			synchronized (messageQueue) {
				while (true) {

                    m = messageQueue.poll();

					if (m == null) {
						try {
							messageQueue.wait();
						} catch (InterruptedException ignored) {
						}
					} else {
						try {
                            if (stopBeforeProcessingNextMessage) {
                                break;
                            }
							process(m);
                        } catch (RuntimeException | OtrException e) {
                            e.printStackTrace();
						}
					}

					if (stopped)
						break;
				}
			}
		}

		public void enqueue(String sender, String s) {
			synchronized (messageQueue) {
				messageQueue.add(new TestMessage(sender, s));
				messageQueue.notifyAll();
			}
		}

		public void stop() {
			stopped = true;

			synchronized (messageQueue) {
				messageQueue.notifyAll();
			}
		}

        public void stopBeforeProcessingNextMessage() {
            stopBeforeProcessingNextMessage = true;
        }

        public TestMessage getNextTestMessage() {
            while (true) {
                if (m == null) {
                    logger.finest("polling");
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    return m;
                }

                if (stopped)
                    return null;
            }
        }
	}

	public class DummyOtrEngineHostImpl implements OtrEngineHost {

	    private final HashMap<SessionID, KeyPair> keypairs = new HashMap<SessionID, KeyPair>();

		public void injectMessage(@Nonnull SessionID sessionID, @Nonnull String msg) {
			connection.send(sessionID.getUserID(), msg);

			String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10)
					+ "..." : msg;
			logger.finest("IM injects message: " + msgDisplay);
		}

		public void smpError(@Nonnull SessionID sessionID, int tlvType, boolean cheated) {
			logger.severe("SM verification error with user: " + sessionID);
			smpQuestions.remove(sessionID);
		}

		public void smpAborted(@Nonnull SessionID sessionID) {
			logger.severe("SM verification has been aborted by user: "
					+ sessionID);
			smpQuestions.remove(sessionID);
		}

		public void finishedSessionMessage(@Nonnull SessionID sessionID, @Nonnull String msgText) {
			logger.severe("SM session was finished. You shouldn't send messages to: "
					+ sessionID);
		}

		public void requireEncryptedMessage(@Nonnull SessionID sessionID, @Nonnull String msgText) {
			logger.severe("Message can't be sent while encrypted session is not established: "
					+ sessionID);
		}

		public void unreadableMessageReceived(@Nonnull SessionID sessionID) {
			logger.warning("Unreadable message received from: " + sessionID);
		}

		public void unencryptedMessageReceived(@Nonnull SessionID sessionID, @Nonnull String msg) {
			logger.warning("Unencrypted message received: " + msg + " from "
					+ sessionID);
		}

		public void showError(@Nonnull SessionID sessionID, @Nonnull String error) {
			logger.severe("IM shows error to user: " + error);
		}

        @Nonnull
		public KeyPair getLocalKeyPair(@Nonnull SessionID paramSessionID) {
            KeyPair keypair = this.keypairs.get(paramSessionID);
            if (keypair == null) {
                try {
                    KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
                    keypair = kg.genKeyPair();
                    this.keypairs.put(paramSessionID, keypair);
                } catch (NoSuchAlgorithmException ex) {
                    throw new IllegalStateException("DSA algorithm unavailable.", ex);
                }
            }
            return keypair;
        }

		public OtrPolicy getSessionPolicy(@Nonnull SessionID ctx) {
			return policy;
		}

        @Nonnull
        public byte[] getLocalFingerprintRaw(@Nonnull SessionID sessionID) {
            return OtrCryptoEngine.getFingerprintRaw(getLocalKeyPair(sessionID)
                    .getPublic());
        }

		public void askForSecret(@Nonnull SessionID sessionID, @Nonnull InstanceTag receiverTag, @Nullable String question) {
            logger.finer("Ask for secret from: " + sessionID
                    + ", instanceTag: " + receiverTag + ", question: " + question);
            smpQuestions.put(sessionID, question);
            if (lock != null)
                lock.countDown();
		}

		public void verify(@Nonnull SessionID sessionID, @Nonnull String fingerprint) {
            logger.finer("Session was verified: " + sessionID);
            verified = VERIFIED;
            if (lock != null)
                lock.countDown();
		}

		public void unverify(@Nonnull SessionID sessionID, @Nonnull String fingerprint) {
            logger.fine("Session was not verified: " + sessionID + "  fingerprint: " + fingerprint);
            verified = UNVERIFIED;
            if (lock != null)
                lock.countDown();
		}

		public String getReplyForUnreadableMessage(@Nonnull SessionID sessionID) {
            return "You sent me an unreadable encrypted message.";
		}

		public String getFallbackMessage(@Nonnull SessionID sessionID) {
            return "Off-the-Record private conversation has been requested. However, you do not have a plugin to support that.";
		}

		public void messageFromAnotherInstanceReceived(@Nonnull SessionID sessionID) {

		}

		public void multipleInstancesDetected(@Nonnull SessionID sessionID) {

		}

		@Override
		public void extraSymmetricKeyDiscovered(@Nonnull SessionID sessionID, @Nonnull String message, @Nonnull byte[] extraSymmetricKey, @Nonnull byte[] tlvData) {
			throw new UnsupportedOperationException("This callback method was not implemented for testing purposes... Please implement if you want to use this in tests.");
		}

		public int getMaxFragmentSize(@Nonnull SessionID sessionID) {
			return Integer.MAX_VALUE;
		}
	}
}
