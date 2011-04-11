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

package com.android.keychain;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.security.Credentials;
import android.security.IKeyChainService;
import android.security.KeyChain;
import android.security.KeyStore;
import android.util.Log;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charsets;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.apache.harmony.luni.util.Base64;

public class KeyChainService extends Service {

    private static final String TAG = "KeyChainService";

    private AccountManager mAccountManager;

    private final Object mAccountLock = new Object();
    private Account mAccount;

    @Override public void onCreate() {
        super.onCreate();
        mAccountManager = AccountManager.get(this);
    }

    private final IKeyChainService.Stub mIKeyChainService = new IKeyChainService.Stub() {

        private final KeyStore mKeyStore = KeyStore.getInstance();

        private boolean isKeyStoreUnlocked() {
            return (mKeyStore.test() == KeyStore.NO_ERROR);
        }

        @Override public byte[] getPrivate(String alias, String authToken) throws RemoteException {
            if (alias == null) {
                throw new NullPointerException("alias == null");
            }
            if (authToken == null) {
                throw new NullPointerException("authToken == null");
            }
            if (!isKeyStoreUnlocked()) {
                throw new IllegalStateException("keystore locked");
            }
            if (!mAccountManager.peekAuthToken(mAccount, alias).equals(authToken)) {
                throw new IllegalStateException("authtoken mismatch");
            }
            String key = Credentials.USER_PRIVATE_KEY + alias;
            byte[] bytes = mKeyStore.get(key.getBytes(Charsets.UTF_8));
            if (bytes == null) {
                throw new IllegalStateException("keystore value missing");
            }
            return bytes;
        }

        @Override public byte[] getCertificate(String alias, String authToken)
                throws RemoteException {
            return getCert(Credentials.USER_CERTIFICATE, alias, authToken);
        }
        @Override public byte[] getCaCertificate(String alias, String authToken)
                throws RemoteException {
            return getCert(Credentials.CA_CERTIFICATE, alias, authToken);
        }

        private byte[] getCert(String type, String alias, String authToken)
                throws RemoteException {
            if (alias == null) {
                throw new NullPointerException("alias == null");
            }
            if (authToken == null) {
                throw new NullPointerException("authtoken == null");
            }
            if (!isKeyStoreUnlocked()) {
                throw new IllegalStateException("keystore locked");
            }
            String authAlias = (type.equals(Credentials.CA_CERTIFICATE))
                    ? (alias + KeyChain.CA_SUFFIX)
                    : alias;
            if (!mAccountManager.peekAuthToken(mAccount, authAlias).equals(authToken)) {
                throw new IllegalStateException("authtoken mismatch");
            }
            String key = type + alias;
            byte[] bytes =  mKeyStore.get(key.getBytes(Charsets.UTF_8));
            if (bytes == null) {
                throw new IllegalStateException("keystore value missing");
            }
            return bytes;
        }

        @Override public String findIssuer(Bundle bundle) {
            if (bundle == null) {
                throw new NullPointerException("bundle == null");
            }
            X509Certificate cert = KeyChain.toCertificate(bundle);
            if (cert == null) {
                throw new IllegalArgumentException("no cert in bundle");
            }
            X500Principal issuer = cert.getIssuerX500Principal();
            if (issuer == null) {
                throw new IllegalStateException();
            }
            byte[] aliasPrefix = Credentials.CA_CERTIFICATE.getBytes(Charsets.UTF_8);
            byte[][] aliasSuffixes = mKeyStore.saw(aliasPrefix);
            if (aliasSuffixes == null) {
                return null;
            }

            // TODO if the keystore would notify us of changes, we
            // could cache the certs and perform a lookup by issuer
            for (byte[] aliasSuffix : aliasSuffixes) {
                byte[] alias = concatenate(aliasPrefix, aliasSuffix);
                byte[] bytes = mKeyStore.get(alias);
                try {
                    // TODO we could at least cache the byte to cert parsing
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    Certificate ca = cf.generateCertificate(new ByteArrayInputStream(bytes));
                    X509Certificate caCert = (X509Certificate) ca;
                    if (issuer.equals(caCert.getSubjectX500Principal())) {
                        // will throw exception on failure to verify.
                        // this can happen if there are two CAs with
                        // the same name but with different public
                        // keys, which does in fact happen, so we will
                        // try to continue and not just fail fast.
                        cert.verify(caCert.getPublicKey());
                        return new String(aliasSuffix, Charsets.UTF_8);
                    }
                } catch (Exception ignored) {
                }
            }
            return null;
        }

        private byte[] concatenate(byte[] a, byte[] b) {
            byte[] result = new byte[a.length + b.length];
            System.arraycopy(a, 0, result, 0, a.length);
            System.arraycopy(b, 0, result, a.length, b.length);
            return result;
        }
    };

    private class KeyChainAccountAuthenticator extends AbstractAccountAuthenticator {

        /**
         * 264 was picked becuase it is the length in bytes of Google
         * authtokens which seems sufficiently long and guaranteed to
         * be storable by AccountManager.
         */
        private final int AUTHTOKEN_LENGTH = 264;
        private final SecureRandom mSecureRandom = new SecureRandom();

        private KeyChainAccountAuthenticator(Context context) {
            super(context);
        }

        @Override public Bundle editProperties(AccountAuthenticatorResponse response,
                                               String accountType) {
            return null;
        }

        @Override public Bundle addAccount(AccountAuthenticatorResponse response,
                                           String accountType,
                                           String authTokenType,
                                           String[] requiredFeatures,
                                           Bundle options) throws NetworkErrorException {
            return null;
        }

        @Override public Bundle confirmCredentials(AccountAuthenticatorResponse response,
                                                   Account account,
                                                   Bundle options) throws NetworkErrorException {
            return null;
        }

        /**
         * Called on an AccountManager cache miss, so generate a new value.
         */
        @Override public Bundle getAuthToken(AccountAuthenticatorResponse response,
                                             Account account,
                                             String authTokenType,
                                             Bundle options) throws NetworkErrorException {
            byte[] bytes = new byte[AUTHTOKEN_LENGTH];
            mSecureRandom.nextBytes(bytes);
            String authToken = Base64.encode(bytes, Charsets.US_ASCII);
            Bundle bundle = new Bundle();
            bundle.putString(AccountManager.KEY_ACCOUNT_NAME, account.name);
            bundle.putString(AccountManager.KEY_ACCOUNT_TYPE, KeyChain.ACCOUNT_TYPE);
            bundle.putString(AccountManager.KEY_AUTHTOKEN, authToken);
            return bundle;
        }

        @Override public String getAuthTokenLabel(String authTokenType) {
            // return authTokenType unchanged, it was a user specified
            // alias name, doesn't need to be localized
            return authTokenType;
        }

        @Override public Bundle updateCredentials(AccountAuthenticatorResponse response,
                                                  Account account,
                                                  String authTokenType,
                                                  Bundle options) throws NetworkErrorException {
            return null;
        }

        @Override public Bundle hasFeatures(AccountAuthenticatorResponse response,
                                            Account account,
                                            String[] features) throws NetworkErrorException {
            return null;
        }
    };

    private final IBinder mAuthenticator = new KeyChainAccountAuthenticator(this).getIBinder();

    @Override public IBinder onBind(Intent intent) {
        if (IKeyChainService.class.getName().equals(intent.getAction())) {

            // ensure singleton keychain account exists
            synchronized (mAccountLock) {
                Account[] accounts = mAccountManager.getAccountsByType(KeyChain.ACCOUNT_TYPE);
                if (accounts.length == 0) {
                    // TODO localize account name
                    mAccount = new Account("Android Key Chain", KeyChain.ACCOUNT_TYPE);
                    mAccountManager.addAccountExplicitly(mAccount, null, null);
                } else if (accounts.length == 1) {
                    mAccount = accounts[0];
                } else {
                    throw new IllegalStateException();
                }
            }

            return mIKeyChainService;
        }

        if (AccountManager.ACTION_AUTHENTICATOR_INTENT.equals(intent.getAction())) {
            return mAuthenticator;
        }

        return null;
    }
}
