package net.java.otr4j.test.dummyclient;

/**
 * Created by gp on 2/6/14.
 */
public interface Server {
	void send(Connection sender, String recipient, String msg);

	Connection connect(DummyClient client);
}
