package com.iscclockk;

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
    public static String TAG ="ISCCLOCKK_MainActivity";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        input = (EditText) findViewById(R.id.input_ori);
        resultText = (TextView) findViewById(R.id.text_result);

        findViewById(R.id.btn_native_encode).setOnClickListener(this);
        findViewById(R.id.btn_native_decode).setOnClickListener(this);

    }


    @Override
    public void onClick(View v) {

        String ori = input.getText().toString().trim();
        String result = "";
        switch (v.getId()) {
            case R.id.btn_native_encode:
                result = nativeEncode(ori);
                break;
            case R.id.btn_native_decode:
                result = nativeDecode(ori);
                break;
        }
        resultText.setText(result);
        input.setText(result);
    }

    private String nativeEncode(String str) {

        return SecureUtil.encode(str);
    }

    private String nativeDecode(String str) {
        return "ISCC{tH15_I5_A_F4KE_fLag}";
    }

}
