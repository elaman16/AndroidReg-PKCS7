package com.vkassin.pkcs.regpkcs7;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;

import com.google.android.gms.appindexing.Action;
import com.google.android.gms.appindexing.AppIndex;
import com.google.android.gms.common.api.GoogleApiClient;

import kz.gamma.core.UtilCM;
import kz.gamma.tumarcsp.DataConverter;
import kz.gamma.tumarcsp.LibraryWrapper;
import kz.gamma.tumarcsp.TumarCspFunctions;

/**
 * Created by vadimkassin on 2/11/16.
 */
public class RegActivity extends Activity {

    /**
     * ATTENTION: This was auto-generated to implement the App Indexing API.
     * See https://g.co/AppIndexing/AndroidStudio for more information.
     */
    private GoogleApiClient client;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reg);
        // ATTENTION: This was auto-generated to implement the App Indexing API.
        // See https://g.co/AppIndexing/AndroidStudio for more information.
        client = new GoogleApiClient.Builder(this).addApi(AppIndex.API).build();
    }

    public void onCloseClick(View view) {
        finish();
    }

    public void onRunClick(View view) {

    }

    /**
     * Функция генерации запроса на сертификат
     *
     * @param profile - профайл
     * @param userID  - идентификатор пользователя
     * @param secret  - секретное слово
     * @return сформированный запрос
     */
    public static byte[] generateCMPIRRequest(String profile, String userID, String secret) {
        byte[] ret = null;
        Number hProv = 0;
        Number hKey = 0;
        Number hKey2 = 0;
        Number hExpKey = 0;

        try {
            hProv = TumarCspFunctions.cpAcquireContext(profile, LibraryWrapper.CRYPT_NEWKEYSET, 0);
            hKey = TumarCspFunctions.cpGenKey(hProv, 0xAA3A, LibraryWrapper.CRYPT_EXPORTABLE);
            hKey2 = TumarCspFunctions.cpGenKey(hProv, 0xA045, LibraryWrapper.CRYPT_EXPORTABLE);
            hExpKey = TumarCspFunctions.cpGenKey(hProv, LibraryWrapper.CALG_CMP_KEY, LibraryWrapper.CRYPT_EXPORTABLE);
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, 79, UtilCM.intToByte(hKey2.intValue(), LibraryWrapper.SUN_CPU_ENDIAN_LITTLE), 0);
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_HASH_ALG, UtilCM.intToByte(LibraryWrapper.CALG_SHA_160, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE), 0);
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_MAC_ALG, UtilCM.intToByte(LibraryWrapper.CALG_MAC, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE), 0);
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_SND_KID, userID.getBytes(), 0);
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_SECRET, DataConverter.stringToByteArray(secret), 0);
            ret = TumarCspFunctions.cpExportKeyData(hProv, hKey, hExpKey, LibraryWrapper.PUBLICKEYBLOB_CMP, 0);
            TumarCspFunctions.cpDestroyKey(hProv, hKey);
            hKey = 0;
            TumarCspFunctions.cpDestroyKey(hProv, hKey2);
            hKey2 = 0;
            TumarCspFunctions.cpDestroyKey(hProv, hExpKey);
            hExpKey = 0;
            TumarCspFunctions.cpReleaseContext(hProv, 0);
        } catch (Exception ex) {
            if (hKey.intValue() != 0) {
                TumarCspFunctions.cpDestroyKey(hProv, hKey);
            }
            if (hKey2.intValue() != 0) {
                TumarCspFunctions.cpDestroyKey(hProv, hKey2);
            }
            if (hExpKey.intValue() != 0)
                TumarCspFunctions.cpDestroyKey(hProv, hExpKey);
            if (hProv.intValue() != 0)
                TumarCspFunctions.cpReleaseContext(hProv, 0);
            ex.printStackTrace();
        }
        return ret;
    }

    @Override
    public void onStart() {
        super.onStart();

        // ATTENTION: This was auto-generated to implement the App Indexing API.
        // See https://g.co/AppIndexing/AndroidStudio for more information.
        client.connect();
        Action viewAction = Action.newAction(
                Action.TYPE_VIEW, // TODO: choose an action type.
                "Reg Page", // TODO: Define a title for the content shown.
                // TODO: If you have web page content that matches this app activity's content,
                // make sure this auto-generated web page URL is correct.
                // Otherwise, set the URL to null.
                Uri.parse("http://host/path"),
                // TODO: Make sure this auto-generated app deep link URI is correct.
                Uri.parse("android-app://com.vkassin.pkcs.regpkcs7/http/host/path")
        );
        AppIndex.AppIndexApi.start(client, viewAction);
    }

    @Override
    public void onStop() {
        super.onStop();

        // ATTENTION: This was auto-generated to implement the App Indexing API.
        // See https://g.co/AppIndexing/AndroidStudio for more information.
        Action viewAction = Action.newAction(
                Action.TYPE_VIEW, // TODO: choose an action type.
                "Reg Page", // TODO: Define a title for the content shown.
                // TODO: If you have web page content that matches this app activity's content,
                // make sure this auto-generated web page URL is correct.
                // Otherwise, set the URL to null.
                Uri.parse("http://host/path"),
                // TODO: Make sure this auto-generated app deep link URI is correct.
                Uri.parse("android-app://com.vkassin.pkcs.regpkcs7/http/host/path")
        );
        AppIndex.AppIndexApi.end(client, viewAction);
        client.disconnect();
    }
}
