package com.vkassin.pkcs.regpkcs7;

import android.content.Intent;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.View;

public class MainActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void onRegClick(View view) {

        Intent intent = new Intent(MainActivity.this, RegActivity.class);
        startActivity(intent);
    }

    public void onSignClick(View view) {
    }
}
