package com.vkassin.pkcs.regpkcs7;

import android.content.Intent;
import android.content.res.AssetManager;
import android.os.Environment;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

import kz.gamma.tumarcsp.LibraryWrapper;
import kz.gamma.tumarcsp.TumarCspFunctions;

public class MainActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if(installLicense()) {
            TumarCspFunctions.initialize(LibraryWrapper.LIBRARY_NAME);
            Log.i("MainActivity", "Licensed to: " + getLicName());
        } else {
            Log.i("MainActivity", "License installation error.");
        }
    }

    public void onRegClick(View view) {

        Intent intent = new Intent(MainActivity.this, RegActivity.class);
        startActivity(intent);
    }

    public void onSignClick(View view) {
    }

    /**
     * Функция установки файла лицензии из каталога assets\TumarCSP
     * @return При успешной установке возвращает true
     */
    boolean installLicense() {

        boolean ret = true;
        try {
            AssetManager localAssetManager = getAssets();
            if ((Environment.getExternalStorageDirectory() != null) && (Environment.getExternalStorageDirectory().canRead())) {
                String dirpath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/TumarCSP/";
                String licPath = dirpath + "cptumar.reg";
                File dir = new File(dirpath);
                if (!dir.exists()) {
                    dir.mkdir();
                }
                File lic = new File(licPath);
                if (!lic.exists()) {
                    String[] files = localAssetManager.list("TumarCSP");
                    InputStream inputStream = localAssetManager.open("TumarCSP/" + files[0]);
                    FileOutputStream outputStream = new FileOutputStream(licPath);
                    byte buf[] = new byte[1024];
                    int len;
                    while ((len = inputStream.read(buf)) != -1) {
                        outputStream.write(buf, 0, len);
                    }
                    outputStream.close();
                    inputStream.close();
                }

            }
        } catch (Exception ex) {
            ret = false;
        }
        return ret;
    }

    /**
     * @return Функция выводит имя организации на которую была сформиована лицензия
     */
    private String getLicName(){
        String ret = null;
        Number hProv = TumarCspFunctions.cpAcquireContext("", LibraryWrapper.CRYPT_VERIFYCONTEXT, 0);
        byte[] blob = TumarCspFunctions.cpGetProvParamByte(hProv , 66, LibraryWrapper.CRYPT_FIRST, 1);
        if(blob!=null){
            ret = new String(blob);
        }
        TumarCspFunctions.cpReleaseContext(hProv, 0);
        return ret;
    }
}
