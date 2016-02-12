package com.vkassin.pkcs.regpkcs7;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.StrictMode;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import com.google.android.gms.appindexing.Action;
import com.google.android.gms.appindexing.AppIndex;
import com.google.android.gms.common.api.GoogleApiClient;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.util.Date;

import kz.gamma.core.Info;
import kz.gamma.core.UtilCM;
import kz.gamma.core.utils.DateUtils;
import kz.gamma.tumarcsp.DataConverter;
import kz.gamma.tumarcsp.ErrorResolver;
import kz.gamma.tumarcsp.LibraryWrapper;
import kz.gamma.tumarcsp.TumarCspFunctions;
import kz.gamma.tumarcsp.exception.CSPException;

import kz.gamma.SampleTumarCSPLibFunction;
/**
 * Created by vadimkassin on 2/11/16.
 */
public class RegActivity extends Activity {

    /**
     * ATTENTION: This was auto-generated to implement the App Indexing API.
     * See https://g.co/AppIndexing/AndroidStudio for more information.
     */
    private GoogleApiClient client;
    private EditText mUserId;
    private EditText mSecret;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_reg);
        // ATTENTION: This was auto-generated to implement the App Indexing API.
        // See https://g.co/AppIndexing/AndroidStudio for more information.
        client = new GoogleApiClient.Builder(this).addApi(AppIndex.API).build();

        mUserId = (EditText)findViewById(R.id.userId);
        mSecret = (EditText)findViewById(R.id.secret);

        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
    }

    public void onCloseClick(View view) {
        finish();
    }

    public void onRunClick(View view) {

        String dirpath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/TumarCSP/";
        String prof = createProfile(dirpath, "key", "1234567890");

        try {
            byte[] req = RegActivity.generateCMPIRRequest(prof, mUserId.getText().toString(), mSecret.getText().toString());
            byte[] resp1 = sendRequest("http://91.195.226.33:62260", req);
            boolean ver = SampleTumarCSPLibFunction.verifyCMPSetIRResponce(prof, mSecret.getText().toString(), resp1);
            if(ver) {
                Log.i("Reg.Activity", "Verify success");
            } else {
                Log.i("Reg.Activity", "Verify error");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static byte[] sendRequest(String urlService, byte[] req) {
        byte[] resp = null;

        try {
            URLConnection ex = (new URL(urlService)).openConnection();
            ex.setRequestProperty("content-type", "application/pkixcmp");
            ex.setDoOutput(true);
            DataOutputStream printout = new DataOutputStream(ex.getOutputStream());
            printout.write(req);
            printout.flush();
            printout.close();
            DataInputStream dataInputStream = new DataInputStream(ex.getInputStream());
            ByteBuffer byteBuffer = ByteBuffer.allocate(8192);
            int count = 0;

            int c;
            while((c = dataInputStream.read()) != -1) {
                byteBuffer.put((byte)c);
                ++count;
                if(count >= 8192) {
                    break;
                }
            }

            resp = UtilCM.copyByte(byteBuffer.array(), 0, count);
        } catch (Exception var9) {
            var9.printStackTrace();
        }

        return resp;
    }

    /**
     * Функция генерации профайла
     * @param path - путь к файлу с ключами (обязательно должен быть доступ к нему)
     * @param fName - имя ключевого контейнера
     * @param pass - пароль
     * @return Возвращает сформированный профайл
     */
    public static String createProfile(String path, String fName, String pass){
        String profile = "";
        Number hProvLocal = TumarCspFunctions.cpAcquireContext("", LibraryWrapper.CRYPT_VERIFYCONTEXT,
                LibraryWrapper.PV_TABLE);
        profile = TumarCspFunctions.cpCreateUrl(fName, "file", fName,
                pass, path, "p12", 0xA045, 0xAA3A, hProvLocal);
        TumarCspFunctions.cpReleaseContext(hProvLocal, 0);
        return profile;
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
            // Создание контекста CSP
            hProv = TumarCspFunctions.cpAcquireContext(profile, LibraryWrapper.CRYPT_NEWKEYSET, 0);
            // Создание ключа подписи CALG_EC256_512G_A
            hKey = TumarCspFunctions.cpGenKey(hProv, 0xAA3A, LibraryWrapper.CRYPT_EXPORTABLE);
            //
            hKey2 = TumarCspFunctions.cpGenKey(hProv, 0xA045, LibraryWrapper.CRYPT_EXPORTABLE);
            // Создание ключа экспорта запроса CMP/Initialization Request. CALG_CMP_KEY is 0xa05a
            hExpKey = TumarCspFunctions.cpGenKey(hProv, LibraryWrapper.CALG_CMP_KEY, LibraryWrapper.CRYPT_EXPORTABLE);
            //
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, 79, UtilCM.intToByte(hKey2.intValue(), LibraryWrapper.SUN_CPU_ENDIAN_LITTLE), 0);
            // Установка алгоритма формирования ключа
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_HASH_ALG, UtilCM.intToByte(LibraryWrapper.CALG_SHA_160, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE), 0);
            // Установка алгоритма защиты с общим секретом 0x8005
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_MAC_ALG, UtilCM.intToByte(LibraryWrapper.CALG_MAC, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE), 0);
            // Установка идентификатора пользователя
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_SND_KID, userID.getBytes(), 0);
            // Установка секрета
            TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_SECRET, DataConverter.stringToByteArray(secret), 0);
            // Формирование запроса
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

    /**
     * Функция проверки ответа, и установки сертификатов в контейнер
     * @param profile  - профайл
     * @param secret   - секретное слово
     * @param resp     - ответ
     * @return В случае ошибки возвращает false
     */
    public static boolean verifyCMPSetIRResponce(String profile, String secret, byte[] resp){
        boolean ret = false;
        Number hProv = 0;
        Number hKey = 0;
        Number hExpKey = 0;
        try{
            hProv = TumarCspFunctions.cpAcquireContext(profile, 0, 0);
            hKey = TumarCspFunctions.cpImportKey(hProv, resp, resp.length, 0, 0);
            byte[] dw = TumarCspFunctions.cpGetKeyParamData(hProv, hKey, LibraryWrapper.KP_CMP_TYPE, 0);
            int type = UtilCM.byteToInt(dw, 0, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE);
            String responseType = Info.codeToResponseType(type);
            if(type == LibraryWrapper.PKI_CMP_ERROR){
                byte[] status = TumarCspFunctions.cpGetKeyParamData(hProv, hKey, LibraryWrapper.KP_CMP_STATUS, LibraryWrapper.ZERO);
                int statusInt = UtilCM.byteToInt(status, 0, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE);
                String errorCmpStatus = Info.codeToFail(statusInt);
                byte[] fail = TumarCspFunctions.cpGetKeyParamData(hProv, hKey, LibraryWrapper.KP_CMP_FAIL, LibraryWrapper.ZERO);
                int failInt = UtilCM.byteToInt(fail, 0, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE);
                String errorCmpFail = null;
                if (failInt != 0xFF) {
                    errorCmpFail = Info.codeToFail(failInt);
                }
                throw new CSPException(new ErrorResolver(hProv), "Проверка ответа на запрос для опроса транзакции завершилась неудачно.\n" +
                        "CMP response type: " + responseType + ".\n" +
                        "Error CMP status: " + errorCmpStatus + ".\n" +
                        "Error CMP fail: " + errorCmpFail);
            }

            byte[] transId = TumarCspFunctions.cpGetKeyParamData(hProv, hKey, LibraryWrapper.KP_CMP_TRANS_ID, LibraryWrapper.ZERO);
            String transactionId = new String(transId);
            int status = 0;

            if(type != LibraryWrapper.PKI_CMP_IP){
                throw new CSPException(new ErrorResolver(hProv), "Ответ неправильного типа");
            }

            byte[] statusBytes = TumarCspFunctions.cpGetKeyParamData(hProv, hKey, LibraryWrapper.KP_CMP_STATUS, LibraryWrapper.ZERO);
            status = UtilCM.byteToInt(statusBytes, 0, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE);
            if (status == LibraryWrapper.PKISTATUS_INFO_WAITING) {
                Date time = null;
                try {
                    byte[] timeBytes = TumarCspFunctions.cpGetKeyParamData(hProv, hKey, LibraryWrapper.KP_CMP_SERVER_WAIT, LibraryWrapper.ZERO);
                    DateUtils dateUtils = DateUtils.getInstance();
                    time = dateUtils.stringToDate(new String(timeBytes));
                } catch (Exception e) {
                    time = null;
                }
                System.out.println("запрос " + transactionId + " ожидает обработки [" + time + "]");
            }else if (status == LibraryWrapper.PKISTATUS_INFO_REJECTION) {
                throw new CSPException(new ErrorResolver(hProv), "Запрос был отклонен");
            } else {

                hExpKey = TumarCspFunctions.cpGenKey(hProv, LibraryWrapper.CALG_CMP_KEY, LibraryWrapper.CRYPT_EXPORTABLE);
                TumarCspFunctions.cpSetKeyParam(hProv, hExpKey, LibraryWrapper.KP_CMP_SECRET, DataConverter.stringToByteArray(secret), 0);

                TumarCspFunctions.cpVerifySignature(hProv, 0, resp, resp.length, hExpKey, "", LibraryWrapper.CRYPT_OBJECT_CMP);
                TumarCspFunctions.cpDestroyKey(hProv, hKey);
                hKey = 0;
                hKey = TumarCspFunctions.cpGetUserKey(hProv, LibraryWrapper.AT_SIGNATURE);
                TumarCspFunctions.cpSetKeyParam(hProv, hKey, LibraryWrapper.KP_CERTIFICATE, resp, 0);
                TumarCspFunctions.cpSetKeyParam(hProv, hKey, LibraryWrapper.KP_CERTIFICATE_CA, resp, 0);

                TumarCspFunctions.cpDestroyKey(hProv, hKey); hKey = 0;
                TumarCspFunctions.cpDestroyKey(hProv, hExpKey); hExpKey = 0;
                TumarCspFunctions.cpReleaseContext(hProv, 0);
            }
            ret = true;
        }
        catch(Exception ex){
            if(hKey.intValue()!=0)
                TumarCspFunctions.cpDestroyKey(hProv, hKey);
            if(hExpKey.intValue()!=0)
                TumarCspFunctions.cpDestroyKey(hProv, hExpKey);
            if(hProv.intValue()!=0)
                TumarCspFunctions.cpReleaseContext(hProv, 0);
            ex.printStackTrace();
        }
        return ret;
    }

    void logMessage(String msg) {

        Log.i("Reg.Activity", msg);

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
