package com.mainli;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private EditText input;
    private TextView resultText;
    public static String TAG ="MainActivity";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        input = (EditText) findViewById(R.id.input_ori);
        resultText = (TextView) findViewById(R.id.text_result);

        findViewById(R.id.btn_native_encode).setOnClickListener(this);
        findViewById(R.id.btn_java_encode).setOnClickListener(this);
        findViewById(R.id.btn_native_decode).setOnClickListener(this);
        findViewById(R.id.btn_java_decode).setOnClickListener(this);

        findViewById(R.id.btn_java_sign).setOnClickListener(this);
        findViewById(R.id.btn_native_sign).setOnClickListener(this);

        try {
            PackageInfo pkgInfo = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
            String sign = pkgInfo.signatures[0].toCharsString();
            Log.i("Mainli", sign.length() + "sign: " + sign);
            Log.i("Mainli", "SIGN_FRONT_DEBUG:" + sign.substring(8, 24));
            Log.i("Mainli", "SIGN_END_DEBUG:" + sign.substring(sign.length() - 24, sign.length() - 8));
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
    }


    @Override
    public void onClick(View v) {

        String ori = input.getText().toString().trim();
        String result = "";
        switch (v.getId()) {
            case R.id.btn_java_encode:
                result = javaEncode(ori);
                break;
            case R.id.btn_native_encode:
                result = nativeEncode(ori);
                break;
            case R.id.btn_java_decode:
                result = javaDecode(ori);
                break;
            case R.id.btn_native_decode:
                result = nativeDecode(ori);
                break;
            case R.id.btn_java_sign:
                result = javaSign(ori);
                break;
            case R.id.btn_native_sign:
                result = nativeSign(ori);
                break;
        }
        resultText.setText(result);
        input.setText(result);
    }


    private String javaEncode(String str) {
        try {
            byte[] key = MD5Util.toByte(getKey());
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = {49, 50, 51, 52, 49, 50, 51, 52, 49, 50, 51, 52, 49, 50, 51, 52};
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(str.getBytes());

            String base64 = Base64.encodeToString(encrypted, Base64.DEFAULT);
            return base64;
        } catch (Exception e) {
            e.printStackTrace();
            return str;
        }
    }

    private String javaDecode(String str) {
        try {
            byte[] deData = Base64.decode(str, Base64.DEFAULT);
            byte[] key = MD5Util.toByte(getKey());
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = {49, 50, 51, 52, 49, 50, 51, 52, 49, 50, 51, 52, 49, 50, 51, 52};
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            byte[] oriData = cipher.doFinal(deData);
            return new String(oriData);
        } catch (Exception e) {
            e.printStackTrace();
            return str;
        }
    }

    public String javaSign(String param) {
        String salt = getSalt();
        String key = salt + param + salt;
        String sign = null;
        try {
            sign = MD5Util.to32Str(key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sign;
    }

    private String nativeEncode(String str) {
        return SecureUtil.encode(str);
    }

    private String nativeDecode(String str) {
        Log.i("Mainli", "nativeDecode: " + str);
        return SecureUtil.decode(str);
    }

    private String nativeSign(String param) {
        return SecureUtil.getSign(param);
    }

    private String getKey() {
        return "appKey" + SecureUtil.getDeviceId() + "appKey";
    }

    private String getSalt() {
        return SecureUtil.getDeviceId() + "appKey" + SecureUtil.getDeviceId();
    }

}
