/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.keychain.tests;

import android.app.Activity;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.KeyChain;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.widget.TextView;
import java.net.Socket;
import java.net.URL;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import libcore.java.security.TestKeyStore;
import libcore.javax.net.ssl.TestSSLContext;
import org.apache.harmony.xnet.provider.jsse.IndexedPKIXParameters;
import org.apache.harmony.xnet.provider.jsse.SSLParametersImpl;
import tests.http.MockResponse;
import tests.http.MockWebServer;

/**
 * Simple activity based test that exercises the KeyChain API
 */
public class KeyChainTestActivity extends Activity {

    private static final String TAG = "KeyChainTestActivity";

    private static final int REQUEST_ALIAS = 1;
    private static final int REQUEST_GRANT = 2;

    private TextView mTextView;

    private KeyChain mKeyChain;

    private final Object mAliasLock = new Object();
    private String mAlias;

    private final Object mGrantedLock = new Object();
    private boolean mGranted;

    private void log(final String message) {
        Log.d(TAG, message);
        runOnUiThread(new Runnable() {
            @Override public void run() {
                mTextView.append(message + "\n");
            }
        });
    }

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mTextView = new TextView(this);
        mTextView.setMovementMethod(new ScrollingMovementMethod());
        setContentView(mTextView);

        log("Starting test...");

        try {
            KeyChain.getInstance(this);
            throw new AssertionError();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (IllegalStateException expected) {
            log("KeyChain failed as expected on main thread.");
        }

        new AsyncTask<Void, Void, Void>() {
            @Override protected Void doInBackground(Void... params) {
                try {
                    mKeyChain = KeyChain.getInstance(KeyChainTestActivity.this);
                    log("Starting web server...");
                    URL url = startWebServer();
                    log("Making https request to " + url);
                    makeHttpsRequest(url);
                    log("Tests succeeded.");

                    return null;
                } catch (Exception e) {
                    throw new AssertionError(e);
                }
            }
            private URL startWebServer() throws Exception {
                KeyStore serverKeyStore = TestKeyStore.getServer().keyStore;
                char[] serverKeyStorePassword = TestKeyStore.getServer().storePassword;
                String kmfAlgoritm = KeyManagerFactory.getDefaultAlgorithm();
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(kmfAlgoritm);
                kmf.init(serverKeyStore, serverKeyStorePassword);
                SSLContext serverContext = SSLContext.getInstance("SSL");
                serverContext.init(kmf.getKeyManagers(),
                                   new TrustManager[] { new TrustAllTrustManager() },
                                   null);
                SSLSocketFactory sf = serverContext.getSocketFactory();
                SSLSocketFactory needClientAuth = TestSSLContext.clientAuth(sf, false, true);
                MockWebServer server = new MockWebServer();
                server.useHttps(needClientAuth, false);
                server.enqueue(new MockResponse().setBody("this response comes via HTTPS"));
                server.play();
                return server.getUrl("/");
            }
            private void makeHttpsRequest(URL url) throws Exception {
                SSLContext clientContext = SSLContext.getInstance("SSL");
                clientContext.init(new KeyManager[] { new KeyChainKeyManager() },
                                   new TrustManager[] { new KeyChainTrustManager() },
                                   null);
                HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
                connection.setSSLSocketFactory(clientContext.getSocketFactory());
                if (connection.getResponseCode() != 200) {
                    throw new AssertionError();
                }
            }
        }.execute();
    }

    /**
     * Called when the user did not have access to requested
     * alias. Ask the user for permission and wait for a result.
     */
    private void waitForGrant(Intent intent) {
        mGranted = false;
        log("Grant intent=" + intent);
        startActivityForResult(intent, REQUEST_GRANT);
        synchronized (mGrantedLock) {
            while (!mGranted) {
                try {
                    mGrantedLock.wait();
                } catch (InterruptedException ignored) {
                }
            }
        }
    }

    private class KeyChainKeyManager extends X509ExtendedKeyManager {
        @Override public String chooseClientAlias(String[] keyTypes,
                                                  Principal[] issuers,
                                                  Socket socket) {
            log("KeyChainKeyManager chooseClientAlias...");

            Intent intent = KeyChain.chooseAlias();
            startActivityForResult(intent, REQUEST_ALIAS);
            log("Starting chooser...");
            String alias;
            synchronized (mAliasLock) {
                while (mAlias == null) {
                    try {
                        mAliasLock.wait();
                    } catch (InterruptedException ignored) {
                    }
                }
                alias = mAlias;
            }
            return alias;
        }
        @Override public String chooseServerAlias(String keyType,
                                                  Principal[] issuers,
                                                  Socket socket) {
            // not a client SSLSocket callback
            throw new UnsupportedOperationException();
        }
        @Override public X509Certificate[] getCertificateChain(String alias) {
            log("KeyChainKeyManager getCertificateChain...");
            Bundle cert = mKeyChain.getCertificate(alias);
            Intent intent = cert.getParcelable(KeyChain.KEY_INTENT);
            if (intent != null) {
                waitForGrant(intent);
                cert = mKeyChain.getCertificate(alias);
            }
            X509Certificate certificate = KeyChain.toCertificate(cert);
            log("certificate=" + certificate);
            return new X509Certificate[] { certificate };
        }
        @Override public String[] getClientAliases(String keyType, Principal[] issuers) {
            // not a client SSLSocket callback
            throw new UnsupportedOperationException();
        }
        @Override public String[] getServerAliases(String keyType, Principal[] issuers) {
            // not a client SSLSocket callback
            throw new UnsupportedOperationException();
        }
        @Override public PrivateKey getPrivateKey(String alias) {
            log("KeyChainKeyManager getPrivateKey...");
            Bundle pkey = mKeyChain.getPrivate(alias);
            Intent intent = pkey.getParcelable(KeyChain.KEY_INTENT);
            if (intent != null) {
                waitForGrant(intent);
                pkey = mKeyChain.getPrivate(alias);
            }
            PrivateKey privateKey = KeyChain.toPrivateKey(pkey);
            log("privateKey=" + privateKey);
            return privateKey;
        }
    }

    private class KeyChainTrustManager implements X509TrustManager {
        private final X509TrustManager trustManager = SSLParametersImpl.getDefaultTrustManager();
        private final IndexedPKIXParameters index
                = SSLParametersImpl.getDefaultIndexedPKIXParameters();

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            // not a client SSLSocket callback
            throw new UnsupportedOperationException();
        }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            log("KeyChainTrustManager checkServerTrusted...");
            // start at the end of the chain and make sure we have a trust anchor.
            // if not, ask KeyChain for one.
            X509Certificate end = chain[chain.length-1];
            if (findTrustAnchor(end)) {
                trustManager.checkServerTrusted(chain, authType);
                return;
            }

            // try to extend the chain
            List<X509Certificate> list = new ArrayList<X509Certificate>(Arrays.asList(chain));
            do {
                Bundle ca = mKeyChain.findIssuer(end);
                if (ca == null) {
                    break;
                }
                Intent intent = ca.getParcelable(KeyChain.KEY_INTENT);
                if (intent != null) {
                    waitForGrant(intent);
                    ca = mKeyChain.findIssuer(end);
                }
                end = KeyChain.toCertificate(ca);
                list.add(end);
            } while (!findTrustAnchor(end));

            // convert extended chain back to array
            if (list.size() != chain.length) {
                chain = list.toArray(new X509Certificate[list.size()]);
            }
            trustManager.checkServerTrusted(chain, authType);
        }

        /**
         * Returns true if we have found a trust anchor, with or
         * without error, indicating that we should call the
         * underlying TrustManager to verify the chain in its current
         * state. Otherwise, returns false to indicate the chain
         * should be extended.
         */
        private boolean findTrustAnchor(X509Certificate cert) {
            try {
                if (index.findTrustAnchor(cert) == null) {
                    return false;
                }
            } catch (CertPathValidatorException ignored) {
            }
            return true;
        }

        @Override public X509Certificate[] getAcceptedIssuers() {
            // not a client SSLSocket callback
            throw new UnsupportedOperationException();
        }
    }

    private static class TrustAllTrustManager implements X509TrustManager {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }
        @Override public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case REQUEST_ALIAS: {
                log("onActivityResult REQUEST_ALIAS...");
                if (resultCode != RESULT_OK) {
                    log("REQUEST_ALIAS failed!");
                    return;
                }
                String alias = data.getExtras().getString(Intent.EXTRA_TEXT);
                log("Alias choosen '" + alias + "'");
                synchronized (mAliasLock) {
                    mAlias = alias;
                    mAliasLock.notifyAll();
                }
                break;
            }
            case REQUEST_GRANT: {
                log("onActivityResult REQUEST_GRANT...");
                if (resultCode != RESULT_OK) {
                    log("REQUEST_GRANT failed!");
                    return;
                }
                synchronized (mGrantedLock) {
                    mGranted = true;
                    mGrantedLock.notifyAll();
                }
                break;
            }
            default:
                throw new IllegalStateException("requestCode == " + requestCode);
        }
    }
}
