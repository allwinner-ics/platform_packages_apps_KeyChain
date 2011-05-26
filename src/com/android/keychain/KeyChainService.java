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
import android.accounts.AccountsException;
import android.accounts.NetworkErrorException;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.security.Credentials;
import android.security.IKeyChainService;
import android.security.KeyChain;
import android.security.KeyStore;
import android.util.Log;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charsets;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import javax.security.auth.x500.X500Principal;
import org.apache.harmony.luni.util.Base64;
import org.apache.harmony.xnet.provider.jsse.TrustedCertificateStore;

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
        private final TrustedCertificateStore mTrustedCertificateStore
                = new TrustedCertificateStore();

        @Override public byte[] getPrivateKey(String alias, String authToken) {
            return getKeyStoreEntry(Credentials.USER_PRIVATE_KEY, alias, authToken);
        }

        @Override public byte[] getCertificate(String alias, String authToken) {
            return getKeyStoreEntry(Credentials.USER_CERTIFICATE, alias, authToken);
        }

        private byte[] getKeyStoreEntry(String type, String alias, String authToken) {
            if (alias == null) {
                throw new NullPointerException("alias == null");
            }
            if (authToken == null) {
                throw new NullPointerException("authtoken == null");
            }
            if (!isKeyStoreUnlocked()) {
                throw new IllegalStateException("keystore locked");
            }
            if (!mAccountManager.peekAuthToken(mAccount, alias).equals(authToken)) {
                throw new IllegalStateException("authtoken mismatch");
            }
            String key = type + alias;
            byte[] bytes =  mKeyStore.get(key.getBytes(Charsets.UTF_8));
            if (bytes == null) {
                throw new IllegalStateException("keystore value missing");
            }
            return bytes;
        }

        private boolean isKeyStoreUnlocked() {
            return (mKeyStore.test() == KeyStore.NO_ERROR);
        }

        @Override public void installCaCertificate(byte[] caCertificate) {
            // only the CertInstaller should be able to add new trusted CAs
            final String expectedPackage = "com.android.certinstaller";
            final String actualPackage = getPackageManager().getNameForUid(getCallingUid());
            if (!expectedPackage.equals(actualPackage)) {
                throw new IllegalStateException(actualPackage);
            }
            try {
                synchronized (mTrustedCertificateStore) {
                    mTrustedCertificateStore.installCertificate(parseCertificate(caCertificate));
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } catch (CertificateException e) {
                throw new IllegalStateException(e);
            }
        }

        private X509Certificate parseCertificate(byte[] bytes) throws CertificateException {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
        }

        @Override public boolean reset() {
            // only Settings should be able to reset
            final String expectedPackage = "android.uid.system:1000";
            final String actualPackage = getPackageManager().getNameForUid(getCallingUid());
            if (!expectedPackage.equals(actualPackage)) {
                throw new IllegalStateException(actualPackage);
            }
            boolean ok = true;

            synchronized (mAccountLock) {
                // remote Accounts from AccountManager to revoke any
                // granted credential grants to applications
                Account[] accounts = mAccountManager.getAccountsByType(KeyChain.ACCOUNT_TYPE);
                for (Account a : accounts) {
                    try {
                        if (!mAccountManager.removeAccount(a, null, null).getResult()) {
                            ok = false;
                        }
                    } catch (AccountsException e) {
                        Log.w(TAG, "Problem removing account " + a, e);
                        ok = false;
                    } catch (IOException e) {
                        Log.w(TAG, "Problem removing account " + a, e);
                        ok = false;
                    }
                }
            }

            synchronized (mTrustedCertificateStore) {
                // delete user-installed CA certs
                for (String alias : mTrustedCertificateStore.aliases()) {
                    if (TrustedCertificateStore.isUser(alias)) {
                        try {
                            mTrustedCertificateStore.deleteCertificateEntry(alias);
                        } catch (IOException e) {
                            Log.w(TAG, "Problem removing CA certificate " + alias, e);
                            ok = false;
                        } catch (CertificateException e) {
                            Log.w(TAG, "Problem removing CA certificate " + alias, e);
                            ok = false;
                        }
                    }
                }
                return ok;
            }
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
                                           Bundle options) {
            return null;
        }

        @Override public Bundle confirmCredentials(AccountAuthenticatorResponse response,
                                                   Account account,
                                                   Bundle options) {
            return null;
        }

        /**
         * Called on an AccountManager cache miss, so generate a new value.
         */
        @Override public Bundle getAuthToken(AccountAuthenticatorResponse response,
                                             Account account,
                                             String authTokenType,
                                             Bundle options) {
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
                                                  Bundle options) {
            return null;
        }

        @Override public Bundle hasFeatures(AccountAuthenticatorResponse response,
                                            Account account,
                                            String[] features) {
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
