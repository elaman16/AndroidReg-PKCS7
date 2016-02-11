package com.vkassin.pkcs.regpkcs7;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;

/**
 * Created by vadimkassin on 2/11/16.
 */
public class RegActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reg);
    }

    public void onCloseClick(View view) {
        finish();
    }

    public void onRunClick(View view) {
        finish();
    }
}
