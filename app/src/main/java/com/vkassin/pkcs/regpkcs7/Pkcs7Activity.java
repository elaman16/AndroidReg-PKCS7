package com.vkassin.pkcs.regpkcs7;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import kz.gamma.core.UtilCM;
import kz.gamma.tumarcsp.LibraryWrapper;
import kz.gamma.tumarcsp.TumarCspFunctions;

/**
 * Created by vadimkassin on 2/15/16.
 */
public class Pkcs7Activity extends Activity {

    private class TextViewUpdater implements Runnable {
        private String txt = "Start";

        @Override
        public void run() {
            mLog.setText(txt);
        }

        public void setText(String txt) {
            this.txt = txt;
        }

        public String getText() {
            return txt;
        }

    }

    private TextView mLog;
    private EditText mText;
    private TextViewUpdater textViewUpdater;
    private Handler textViewUpdaterHandler;
    private byte[] sign;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pkcs7);
        mLog = (TextView)findViewById(R.id.textView1);
        mLog.setMovementMethod(new ScrollingMovementMethod());
        mText = (EditText)findViewById(R.id.textId);
        textViewUpdater = new TextViewUpdater();
        textViewUpdaterHandler = new Handler(Looper.getMainLooper());
    }

    public void onCloseClick(View view) {

        finish();
    }

    public void onRunClick(View view) {
        String dirpath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/TumarCSP/";
        String prof = createProfile(dirpath, "key", "1234567890");

        try {
            logMessage("Лицензия: " + getLicName());
            logMessage("Формирование запроса на сервер");
            logMessage("Профайл: " + prof);

            sign = signText(prof, mText.getText().toString().getBytes(), true);
            String signStr = "error";
            try {
                signStr = new String(sign, "UTF-8");
            }catch (Exception e){

            }
            logMessage("Подпись: " + signStr);

            // Получение серийного номера сертификата подписанта
//            Number hProv = TumarCspFunctions.cpAcquireContext(profile, 0, 0);
//            Number hHash = TumarCspFunctions.cpCreateHash(hProv, 0x801d, 0, 0);
//            TumarCspFunctions.cpGetHashParamData()
//            TumarCspFunctions.cpHashData(hProv, hHash, data, data.length, 0);
//
//            byte[] dw = TumarCspFunctions.cpGetHashParamData(hProv, hHash, LibraryWrapper.HP_TSTAMP_STSTUS, 0);
//            int code = UtilCM.byteToInt(dw, 0, LibraryWrapper.SUN_CPU_ENDIAN_LITTLE);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void onEmailClick(View view) {

        String signStr = "error";
        try {
            signStr = new String(sign, "UTF-8");
        }catch (Exception e){

        }
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("message/rfc822");
        i.putExtra(Intent.EXTRA_EMAIL  , new String[]{"recipient@example.com"});
        i.putExtra(Intent.EXTRA_SUBJECT, "pkcs7");
        i.putExtra(Intent.EXTRA_TEXT   , signStr);
        try {
            startActivity(Intent.createChooser(i, "Send mail..."));
        } catch (android.content.ActivityNotFoundException ex) {
            Toast.makeText(Pkcs7Activity.this, "There are no email clients installed.", Toast.LENGTH_SHORT).show();
        }
    }

    void logMessage(final String msg) {

        Log.i("Reg.Activity", msg);
        String text = textViewUpdater.getText();
//                String text = mLog.getText().toString();
//                mLog.setText(text + "\n ----------------------------------------- \n" + msg);

        textViewUpdater.setText(text + "\n ----------------------------------------- \n" + msg);
        textViewUpdaterHandler.post(textViewUpdater);
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
     * Функция формирование подписи
     * @param profile - Профайл с ключами для подписи
     * @param text - Блок данных для подписи
     * @param isPKCS7 - Формат подписи
     *                true - Формировать подпись в формате PKCS#7
     *                false - Простая подпись
     * @return Возвращает подпись.
     */
    public static byte [] signText(String profile, byte[] text, boolean isPKCS7){
        byte[]ret = null;
        Number hProv = 0;
        Number hHash = 0;
        try{
            hProv = TumarCspFunctions.cpAcquireContext(profile, 0, 0);
            hHash = TumarCspFunctions.cpCreateHash(hProv, 0x801d, 0, 0);
            TumarCspFunctions.cpHashData(hProv, hHash, text, text.length, 0);
            if(isPKCS7){
                ret = TumarCspFunctions.cpSignHashData(hProv, hHash, LibraryWrapper.AT_SIGNATURE, null, LibraryWrapper.CRYPT_SIGN_PKCS7);
            }else{
                ret = TumarCspFunctions.cpSignHashData(hProv, hHash, LibraryWrapper.AT_SIGNATURE, null, 0);
            }
            TumarCspFunctions.cpDestroyHash(hProv, hHash); hHash = 0;
            TumarCspFunctions.cpReleaseContext(hProv, 0); hProv = 0;
        }
        catch (Exception ex){
            if(hHash.intValue()!=0){
                TumarCspFunctions.cpDestroyHash(hProv, hHash);
            }
            if(hProv.intValue()!=0){
                TumarCspFunctions.cpReleaseContext(hProv, 0);
            }
            ex.printStackTrace();
        }
        return ret;
    }
    /**
     * Функция проверки подписи
     * @param text - Блок данных
     * @param sign - подпись
     * @param signCert - сертификат для проверки подписи
     * @param isPKCS7 - Формат подписи
     *                true - Формировать подпись в формате PKCS#7
     *                false - Простая подпись
     * @return Возвращает true если подпись проверилась
     */
    public static boolean verifySign(byte []text, byte []sign, byte []signCert, boolean isPKCS7){
        boolean ret = false;
        Number hProv = 0;
        Number hHash = 0;
        Number hKey = 0;
        try{

            hProv = TumarCspFunctions.cpAcquireContext("", LibraryWrapper.CRYPT_VERIFYCONTEXT, 0);
            hHash = TumarCspFunctions.cpCreateHash(hProv, 0x801d, 0, 0);
            hKey = TumarCspFunctions.cpImportKey(hProv, signCert, signCert.length, 0, 0);
            if (isPKCS7){
                TumarCspFunctions.cpSetHashParam(hProv, hHash, LibraryWrapper.HP_PKCS7_BODY, sign, 0);
            }
            TumarCspFunctions.cpHashData(hProv, hHash, text, text.length, 0);
            TumarCspFunctions.cpVerifyObjectSignature(hProv, hHash, sign, sign.length, hKey, null, 0);
            TumarCspFunctions.cpDestroyHash(hProv, hHash); hHash = 0;
            TumarCspFunctions.cpDestroyKey(hProv, hKey); hKey = 0;
            TumarCspFunctions.cpReleaseContext(hProv, 0); hProv = 0;
            ret = true;
        }
        catch (Exception ex){
            if(hHash.intValue()!=0){
                TumarCspFunctions.cpDestroyHash(hProv, hHash);
            }
            if(hKey.intValue()!=0){
                TumarCspFunctions.cpDestroyKey(hProv, hKey);
            }
            if(hProv.intValue()!=0){
                TumarCspFunctions.cpReleaseContext(hProv, 0);
            }
            ex.printStackTrace();
        }
        return ret;
    }

    /**
     * @return Функция выводит имя организации на которую была сформиована лицензия
     */
    private String getLicName(){
        String ret = null;
        Number hProv = TumarCspFunctions.cpAcquireContext("", LibraryWrapper.CRYPT_VERIFYCONTEXT, 0);
        byte[] blob = TumarCspFunctions.cpGetProvParamByte(hProv, 66, LibraryWrapper.CRYPT_FIRST, 1);
        if(blob!=null){
            ret = new String(blob);
        }
        TumarCspFunctions.cpReleaseContext(hProv, 0);
        return ret;
    }
}
