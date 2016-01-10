package net.java.otr4j;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.session.SessionID;

import org.bouncycastle.util.encoders.Base64;

public class OtrKeyManagerImpl implements OtrKeyManager {

	private final OtrKeyManagerStore store;

    // TODO consider replacing Vector with ArrayList (need to ensure correct synchronization everywhere)
	private final List<OtrKeyManagerListener> listeners = new Vector<OtrKeyManagerListener>();

	public OtrKeyManagerImpl(final OtrKeyManagerStore store) {
		this.store = store;
	}

	class DefaultPropertiesStore implements OtrKeyManagerStore {
		private final Properties properties = new Properties();
		private final String filepath;

		public DefaultPropertiesStore(final String filepath) throws IOException {
			if (filepath == null || filepath.length() < 1) {
                throw new IllegalArgumentException();
            }
			this.filepath = filepath;
			properties.clear();

			final InputStream in = new BufferedInputStream(new FileInputStream(
					getConfigurationFile()));
			try {
				properties.load(in);
			} finally {
				in.close();
			}
		}

		private File getConfigurationFile() throws IOException {
			final File configFile = new File(filepath);
			if (!configFile.exists()) {
                configFile.createNewFile();
            }
			return configFile;
		}

        @Override
		public void setProperty(final String id, final boolean value) {
			properties.setProperty(id, "true");
			try {
				this.store();
			} catch (Exception e) {
                // TODO replace printStackTrace() call
				e.printStackTrace();
			}
		}

		private void store() throws FileNotFoundException, IOException {
            final OutputStream out = new FileOutputStream(getConfigurationFile());
            try {
                properties.store(out, null);
            } finally {
                out.close();
            }
		}

        @Override
		public void setProperty(final String id, final byte[] value) {
			properties.setProperty(id, new String(Base64.encode(value)));
			try {
				this.store();
			} catch (Exception e) {
                // TODO replace printStackTrace() call
				e.printStackTrace();
			}
		}

        @Override
		public void removeProperty(final String id) {
			properties.remove(id);
		}

        @Override
		public byte[] getPropertyBytes(final String id) {
			final String value = properties.getProperty(id);
			if (value == null) {
                return null;
            }
			return Base64.decode(value);
		}

        @Override
		public boolean getPropertyBoolean(final String id, final boolean defaultValue) {
			try {
				return Boolean.valueOf(properties.get(id).toString());
			} catch (Exception e) {
				return defaultValue;
			}
		}
	}

	public OtrKeyManagerImpl(final String filepath) throws IOException {
		this.store = new DefaultPropertiesStore(filepath);
	}

    @Override
	public void addListener(final OtrKeyManagerListener l) {
		synchronized (listeners) {
			if (!listeners.contains(l)) {
                listeners.add(l);
            }
		}
	}

    @Override
	public void removeListener(final OtrKeyManagerListener l) {
		synchronized (listeners) {
			listeners.remove(l);
		}
	}

    @Override
	public void generateLocalKeyPair(final SessionID sessionID) {
		if (sessionID == null) {
            return;
        }

		final String accountID = sessionID.getAccountID();
		final KeyPair keyPair;
		try {
			keyPair = KeyPairGenerator.getInstance("DSA").genKeyPair();
		} catch (NoSuchAlgorithmException e) {
            // TODO replace printStackTrace() call
			e.printStackTrace();
			return;
		}

		// Store Public Key.
		final PublicKey pubKey = keyPair.getPublic();
        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubKey
                .getEncoded());

		this.store.setProperty(accountID + ".publicKey", x509EncodedKeySpec
				.getEncoded());

		// Store Private Key.
		final PrivateKey privKey = keyPair.getPrivate();
		final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privKey.getEncoded());

		this.store.setProperty(accountID + ".privateKey", pkcs8EncodedKeySpec
				.getEncoded());
	}

    @Override
	public String getLocalFingerprint(final SessionID sessionID) {
		final KeyPair keyPair = loadLocalKeyPair(sessionID);

		if (keyPair == null) {
            return null;
        }

		final PublicKey pubKey = keyPair.getPublic();

		try {
			return OtrCryptoEngine.getFingerprint(pubKey);
		} catch (OtrCryptoException e) {
            // TODO replace printStackTrace() call
			e.printStackTrace();
			return null;
		}
	}

    @Override
	public byte[] getLocalFingerprintRaw(final SessionID sessionID) {
		final KeyPair keyPair = loadLocalKeyPair(sessionID);

		if (keyPair == null) {
            return null;
        }

		final PublicKey pubKey = keyPair.getPublic();

		try {
			return OtrCryptoEngine.getFingerprintRaw(pubKey);
		} catch (OtrCryptoException e) {
            // TODO replace printStackTrace() call
			e.printStackTrace();
			return null;
		}
	}

    @Override
	public String getRemoteFingerprint(final SessionID sessionID) {
		final PublicKey remotePublicKey = loadRemotePublicKey(sessionID);
		if (remotePublicKey == null) {
            return null;
        }
		try {
			return OtrCryptoEngine.getFingerprint(remotePublicKey);
		} catch (OtrCryptoException e) {
            // TODO replace printStackTrace() call
			e.printStackTrace();
			return null;
		}
	}

    @Override
	public boolean isVerified(final SessionID sessionID) {
		if (sessionID == null) {
            // TODO what about SessionID.EMPTY? SessionID.EMPTY has user id 'null', so seems like that is not a good key for the properties store.
            return false;
        }

		return this.store.getPropertyBoolean(sessionID.getUserID()
				+ ".publicKey.verified", false);
	}

    @Override
	public KeyPair loadLocalKeyPair(final SessionID sessionID) {
		if (sessionID == null) {
            // TODO what about SessionID.EMPTY? SessionID.EMPTY has account id 'null', so seems like that is not a good key for the properties store.
            return null;
        }

		final String accountID = sessionID.getAccountID();
		// Load Private Key.
		final byte[] b64PrivKey = this.store.getPropertyBytes(accountID
				+ ".privateKey");
		if (b64PrivKey == null) {
            return null;
        }

		final PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(b64PrivKey);

		// Load Public Key.
		final byte[] b64PubKey = this.store
				.getPropertyBytes(accountID + ".publicKey");
		if (b64PubKey == null) {
            return null;
        }

		final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(b64PubKey);

		final PublicKey publicKey;
		final PrivateKey privateKey;

		// Generate KeyPair.
		try {
            // TODO extract constant for DSA sig alg
			final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			publicKey = keyFactory.generatePublic(publicKeySpec);
			privateKey = keyFactory.generatePrivate(privateKeySpec);
		} catch (NoSuchAlgorithmException e) {
            // TODO replace printStackTrace() call
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
            // TODO replace printStackTrace() call
			e.printStackTrace();
			return null;
		}

		return new KeyPair(publicKey, privateKey);
	}

    @Override
	public PublicKey loadRemotePublicKey(final SessionID sessionID) {
		if (sessionID == null) {
            // TODO what about SessionID.EMPTY? SessionID.EMPTY has user id 'null', so seems like that is not a good key for the properties store.
            return null;
        }

		final String userID = sessionID.getUserID();

		final byte[] b64PubKey = this.store.getPropertyBytes(userID + ".publicKey");
		if (b64PubKey == null) {
            return null;
        }

		final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(b64PubKey);

		// Generate KeyPair.
		try {
			final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			return keyFactory.generatePublic(publicKeySpec);
		} catch (NoSuchAlgorithmException e) {
            // TODO replace printStackTrace() call
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
            // TODO replace printStackTrace() call
			e.printStackTrace();
			return null;
		}
	}

    @Override
	public void savePublicKey(final SessionID sessionID, final PublicKey pubKey) {
		if (sessionID == null) {
            return;
        }

        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubKey
                .getEncoded());

		final String userID = sessionID.getUserID();
		this.store.setProperty(userID + ".publicKey", x509EncodedKeySpec
				.getEncoded());

		this.store.removeProperty(userID + ".publicKey.verified");
	}

    @Override
	public void unverify(final SessionID sessionID) {
		if (sessionID == null) {
            // TODO what about SessionID.EMPTY? SessionID.EMPTY has user id 'null', so seems like that is not a good key for the properties store.
            return;
        }

		if (!isVerified(sessionID)) {
            return;
        }

		this.store
				.removeProperty(sessionID.getUserID() + ".publicKey.verified");

        // TODO do we need synchronization on listeners here?
		for (final OtrKeyManagerListener l : listeners) {
            // TODO consider try-catching RTEs to avoid exception from listener to interfere with process
            l.verificationStatusChanged(sessionID);
        }
	}

    @Override
	public void verify(final SessionID sessionID) {
		if (sessionID == null) {
            // TODO what about SessionID.EMPTY? SessionID.EMPTY has user id 'null', so seems like that is not a good key for the properties store.
            return;
        }

		if (this.isVerified(sessionID)) {
            return;
        }

		this.store.setProperty(sessionID.getUserID() + ".publicKey.verified",
				true);

        // TODO do we need synchronization on listeners here?
		for (final OtrKeyManagerListener l : listeners) {
            // TODO consider try-catching RTEs to avoid exception from listener to interfere with process
			l.verificationStatusChanged(sessionID);
        }
	}
}
