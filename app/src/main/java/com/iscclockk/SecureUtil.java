package com.iscclockk;


import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.provider.Settings;
import android.support.v4.app.ActivityCompat;
import android.util.Base64;
import android.util.Log;

import java.util.Random;


public class SecureUtil {

    public static String encode(String data) {
        return new String(Base64.encode(encryptData(BaseApplication.getInstance(), data.getBytes()), Base64.DEFAULT));
    }

    public static String decode(String data) {
        String s;
        try {
            s = new String(decryptData(BaseApplication.getInstance(), Base64.decode(data, Base64.DEFAULT)));
        } catch (Exception e) {
            s = "";
        }
        return s;
    }

    public static String getDeviceId(Context context) {
        return getPackageSignature(context);
    }

    public static String getPackageSignature(Context context){
        String sign = "";
        final String TAG = "SIGN";
        try {
            PackageInfo pkgInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            sign = pkgInfo.signatures[0].toCharsString();
            //Log.i(TAG, sign.length() + "sign: " + sign);
            //Log.i(TAG, "SIGN_FRONT_DEBUG:" + sign.substring(8, 24));
            //Log.i(TAG, "SIGN_END_DEBUG:" + sign.substring(sign.length() - 24, sign.length() - 8));
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return sign;
    }

    public static String getAppVersion() {
        return BuildConfig.VERSION_NAME;
    }

    public static String getChannel() {
        return "iscclockk";
    }



    public static void showMeg(String tips) {
        Log.w("ISCCLOCKK", "tips: " + tips);

    }

    private native static byte[] encryptData(Context context, byte[] data);

    private native static byte[] decryptData(Context context, byte[] data);


    static {
        System.loadLibrary("Libs");
    }
}
