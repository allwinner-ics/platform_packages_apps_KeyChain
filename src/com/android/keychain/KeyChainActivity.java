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

import android.app.ListActivity;
import android.content.Intent;
import android.os.Bundle;
import android.security.Credentials;
import android.security.KeyStore;
import android.view.View;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

public class KeyChainActivity extends ListActivity {

    private static final String TAG = "KeyChainActivity";

    private static String KEY_STATE = "state";

    private static final int REQUEST_UNLOCK = 1;

    private static enum State { INITIAL, UNLOCK_REQUESTED };

    private State mState;

    private KeyStore mKeyStore = KeyStore.getInstance();

    private boolean isKeyStoreUnlocked() {
        return mKeyStore.test() == KeyStore.NO_ERROR;
    }

    @Override public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        if (savedState == null) {
            mState = State.INITIAL;
        } else {
            mState = (State) savedState.getSerializable(KEY_STATE);
            if (mState == null) {
                mState = State.INITIAL;
            }
        }
    }

    @Override public void onResume() {
        super.onResume();

        // see if KeyStore has been unlocked, if not start activity to do so
        switch (mState) {
            case INITIAL:
                if (!isKeyStoreUnlocked()) {
                    mState = State.UNLOCK_REQUESTED;
                    this.startActivityForResult(new Intent(Credentials.UNLOCK_ACTION),
                                                REQUEST_UNLOCK);
                    // Note that Credentials.unlock will start an
                    // Activity and we will be paused but then resumed
                    // when the unlock Activity completes and our
                    // onActivityResult is called with REQUEST_UNLOCK
                    return;
                }
                showAliasList();
                return;
            case UNLOCK_REQUESTED:
                // we've already asked, but have not heard back, probably just rotated.
                // wait to hear back via onActivityResult
                return;
            default:
                throw new AssertionError();
        }
    }

    private void showAliasList() {

        String[] aliases = mKeyStore.saw(Credentials.USER_PRIVATE_KEY);
        if (aliases == null || aliases.length == 0) {
            setResult(RESULT_CANCELED);
            finish();
            return;
        }

        final ArrayAdapter<String> adapter
                = new ArrayAdapter<String>(this,
                                           android.R.layout.simple_list_item_1,
                                           aliases);
        setListAdapter(adapter);

        ListView lv = getListView();
        lv.setTextFilterEnabled(true);
        lv.setOnItemClickListener(new OnItemClickListener() {
            @Override public void onItemClick(AdapterView<?> parent,
                                              View view,
                                              int position,
                                              long id) {
                String alias = adapter.getItem(position);
                Intent result = new Intent();
                result.putExtra(Intent.EXTRA_TEXT, alias);
                setResult(RESULT_OK, result);
                finish();
            }
        });
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case REQUEST_UNLOCK:
                if (isKeyStoreUnlocked()) {
                    showAliasList();
                } else {
                    // user must have canceled unlock, give up
                    finish();
                }
                return;
            default:
                throw new AssertionError();
        }
    }

    @Override protected void onSaveInstanceState(Bundle savedState) {
        super.onSaveInstanceState(savedState);
        if (mState != State.INITIAL) {
            savedState.putSerializable(KEY_STATE, mState);
        }
    }
}
