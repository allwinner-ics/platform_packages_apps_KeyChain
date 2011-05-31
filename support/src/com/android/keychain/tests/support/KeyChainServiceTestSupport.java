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

package com.android.keychain.tests.support;

import android.accounts.Account;
import android.accounts.AccountManagerService;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.security.KeyStore;
import android.util.Log;

public class KeyChainServiceTestSupport extends Service {

    private static final String TAG = "KeyChainServiceTestSupport";

    private final Object mServiceLock = new Object();
    private IKeyChainServiceTestSupport mService;
    private boolean mIsBound;

    private final KeyStore mKeyStore = KeyStore.getInstance();
    private final AccountManagerService accountManagerService
            = AccountManagerService.getSingleton();

    private final IKeyChainServiceTestSupport.Stub mIKeyChainServiceTestSupport
            = new IKeyChainServiceTestSupport.Stub() {
        @Override public boolean keystoreReset() {
            Log.d(TAG, "keystoreReset");
            return mKeyStore.reset();
        }
        @Override public boolean keystorePassword(String password) {
            Log.d(TAG, "keystorePassword");
            return mKeyStore.password(password);
        }
        @Override public boolean keystorePut(String key, byte[] value) {
            Log.d(TAG, "keystorePut");
            return mKeyStore.put(key, value);
        }
        @Override public void revokeAppPermission(Account account, String authTokenType, int uid) {
            Log.d(TAG, "revokeAppPermission");
            accountManagerService.revokeAppPermission(account, authTokenType, uid);
        }
        @Override public void grantAppPermission(Account account, String authTokenType, int uid) {
            Log.d(TAG, "grantAppPermission");
            accountManagerService.grantAppPermission(account, authTokenType, uid);
        }
    };

    @Override public IBinder onBind(Intent intent) {
        if (IKeyChainServiceTestSupport.class.getName().equals(intent.getAction())) {
            return mIKeyChainServiceTestSupport;
        }
        return null;
    }
}
