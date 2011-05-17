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

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerFuture;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.security.Credentials;
import android.security.IKeyChainService;
import android.security.KeyChain;
import android.security.KeyStore;
import android.util.Log;
import com.android.keychain.tests.support.IKeyChainServiceTestSupport;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.Arrays;
import junit.framework.Assert;
import libcore.java.security.TestKeyStore;

public class KeyChainServiceTest extends Service {

    private static final String TAG = "KeyChainServiceTest";

    private final Object mSupportLock = new Object();
    private IKeyChainServiceTestSupport mSupport;
    private boolean mIsBoundSupport;

    private final Object mServiceLock = new Object();
    private IKeyChainService mService;
    private boolean mIsBoundService;

    private ServiceConnection mSupportConnection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder service) {
            synchronized (mSupportLock) {
                mSupport = IKeyChainServiceTestSupport.Stub.asInterface(service);
                mSupportLock.notifyAll();
            }
        }

        @Override public void onServiceDisconnected(ComponentName name) {
            synchronized (mSupportLock) {
                mSupport = null;
            }
        }
    };

    private ServiceConnection mServiceConnection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder service) {
            synchronized (mServiceLock) {
                mService = IKeyChainService.Stub.asInterface(service);
                mServiceLock.notifyAll();
            }
        }

        @Override public void onServiceDisconnected(ComponentName name) {
            synchronized (mServiceLock) {
                mService = null;
            }
        }
    };

    private void bindSupport() {
        mIsBoundSupport = bindService(new Intent(IKeyChainServiceTestSupport.class.getName()),
                                      mSupportConnection,
                                      Context.BIND_AUTO_CREATE);
    }

    private void bindService() {
        mIsBoundService = bindService(new Intent(IKeyChainService.class.getName()),
                                      mServiceConnection,
                                      Context.BIND_AUTO_CREATE);
    }

    private void unbindServices() {
        if (mIsBoundSupport) {
            unbindService(mSupportConnection);
            mIsBoundSupport = false;
        }
        if (mIsBoundService) {
            unbindService(mServiceConnection);
            mIsBoundService = false;
        }
    }

    @Override public IBinder onBind(Intent intent) {
        Log.d(TAG, "onBind");
        return null;
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand");
        new Thread(new Test(), TAG).start();
        return START_STICKY;
    }

    @Override public void onDestroy () {
        Log.d(TAG, "onDestroy");
        unbindServices();
    }

    private final class Test extends Assert implements Runnable {

        @Override public void run() {
            try {
                test_KeyChainService();
            } catch (RuntimeException e) {
                // rethrow RuntimeException without wrapping
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                stopSelf();
            }
        }

        public void test_KeyChainService() throws Exception {
            Log.d(TAG, "test_KeyChainService uid=" + getApplicationInfo().uid);

            Log.d(TAG, "test_KeyChainService bind support");
            bindSupport();
            assertTrue(mIsBoundSupport);
            synchronized (mSupportLock) {
                if (mSupport == null) {
                    mSupportLock.wait(10 * 1000);
                }
            }
            assertNotNull(mSupport);

            Log.d(TAG, "test_KeyChainService setup keystore and AccountManager");
            KeyStore keyStore = KeyStore.getInstance();
            assertTrue(mSupport.keystoreReset());
            assertTrue(mSupport.keystorePassword("ignored", "newpasswd"));

            String intermediate = "-intermediate";
            String root = "-root";

            String alias1 = "client";
            String alias1Intermediate = alias1 + intermediate;
            String alias1Root = alias1 + root;
            byte[] alias1Pkey = (Credentials.USER_PRIVATE_KEY + alias1).getBytes();
            byte[] alias1Cert = (Credentials.USER_CERTIFICATE + alias1).getBytes();
            byte[] alias1ICert = (Credentials.CA_CERTIFICATE + alias1Intermediate).getBytes();
            byte[] alias1RCert = (Credentials.CA_CERTIFICATE + alias1Root).getBytes();
            PrivateKeyEntry pke1 = TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
            Certificate intermediate1 = pke1.getCertificateChain()[1];
            Certificate root1 = TestKeyStore.getClientCertificate().getRootCertificate("RSA");

            final String alias2 = "server";
            String alias2Intermediate = alias2 + intermediate;
            String alias2Root = alias2 + root;
            byte[] alias2Pkey = (Credentials.USER_PRIVATE_KEY + alias2).getBytes();
            byte[] alias2Cert = (Credentials.USER_CERTIFICATE + alias2).getBytes();
            byte[] alias2ICert = (Credentials.CA_CERTIFICATE + alias2Intermediate).getBytes();
            byte[] alias2RCert = (Credentials.CA_CERTIFICATE + alias2Root).getBytes();
            PrivateKeyEntry pke2 = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
            Certificate intermediate2 = pke2.getCertificateChain()[1];
            Certificate root2 = TestKeyStore.getServer().getRootCertificate("RSA");

            assertTrue(mSupport.keystorePut(alias1Pkey, pke1.getPrivateKey().getEncoded()));
            assertTrue(mSupport.keystorePut(alias1Cert, pke1.getCertificate().getEncoded()));
            assertTrue(mSupport.keystorePut(alias1ICert, intermediate1.getEncoded()));
            assertTrue(mSupport.keystorePut(alias1RCert, root1.getEncoded()));
            assertTrue(mSupport.keystorePut(alias2Pkey, pke2.getPrivateKey().getEncoded()));
            assertTrue(mSupport.keystorePut(alias2Cert, pke2.getCertificate().getEncoded()));
            assertTrue(mSupport.keystorePut(alias2ICert, intermediate2.getEncoded()));
            assertTrue(mSupport.keystorePut(alias2RCert, root2.getEncoded()));

            assertEquals(KeyStore.NO_ERROR, keyStore.test());
            AccountManager accountManager = AccountManager.get(KeyChainServiceTest.this);
            assertNotNull(accountManager);
            for (Account account : accountManager.getAccountsByType(KeyChain.ACCOUNT_TYPE)) {
                mSupport.revokeAppPermission(account, alias1, getApplicationInfo().uid);
                mSupport.revokeAppPermission(account, alias2, getApplicationInfo().uid);
            }

            Log.d(TAG, "test_KeyChainService bind service");
            bindService();
            assertTrue(mIsBoundService);
            synchronized (mServiceLock) {
                if (mService == null) {
                    mServiceLock.wait(10 * 1000);
                }
            }
            assertNotNull(mService);

            Account[] accounts = accountManager.getAccountsByType(KeyChain.ACCOUNT_TYPE);
            assertNotNull(accounts);
            assertEquals(1, accounts.length);
            Account account = accounts[0];
            Log.d(TAG, "test_KeyChainService getAuthTokenByFeatures for Intent");
            AccountManagerFuture<Bundle> accountManagerFutureFail
                    = accountManager.getAuthToken(account, alias1, false, null, null);
            Bundle bundleFail = accountManagerFutureFail.getResult();
            assertNotNull(bundleFail);
            Object intentObject = bundleFail.get(AccountManager.KEY_INTENT);
            assertNotNull(intentObject);
            assertTrue(Intent.class.isAssignableFrom(intentObject.getClass()));
            Intent intent = (Intent) intentObject;
            assertEquals("android",
                         intent.getComponent().getPackageName());
            assertEquals("android.accounts.GrantCredentialsPermissionActivity",
                         intent.getComponent().getClassName());

            mSupport.grantAppPermission(account, alias1, getApplicationInfo().uid);
            // don't grant alias2, so it can be done manually with KeyChainTestActivity
            Log.d(TAG, "test_KeyChainService getAuthTokenByFeatures for authtoken");
            AccountManagerFuture<Bundle> accountManagerFuture
                    = accountManager.getAuthToken(account, alias1, false, null, null);
            Bundle bundle = accountManagerFuture.getResult();
            String accountName = bundle.getString(AccountManager.KEY_ACCOUNT_NAME);
            assertNotNull(accountName);
            String accountType = bundle.getString(AccountManager.KEY_ACCOUNT_TYPE);
            assertEquals(KeyChain.ACCOUNT_TYPE, accountType);
            String authToken = bundle.getString(AccountManager.KEY_AUTHTOKEN);
            assertNotNull(authToken);
            assertFalse(authToken.isEmpty());

            byte[] privateKey = mService.getPrivateKey(alias1, authToken);
            assertNotNull(privateKey);
            assertEquals(Arrays.toString(pke1.getPrivateKey().getEncoded()),
                         Arrays.toString(privateKey));

            byte[] certificate = mService.getCertificate(alias1, authToken);
            assertNotNull(certificate);
            assertEquals(Arrays.toString(pke1.getCertificate().getEncoded()),
                         Arrays.toString(certificate));

            Log.d(TAG, "test_KeyChainService unbind");
            unbindServices();
            assertFalse(mIsBoundSupport);
            assertFalse(mIsBoundService);

            Log.d(TAG, "test_KeyChainService end");
        }
    }
}
