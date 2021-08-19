package com.mainli;


import android.content.Context;
import android.util.Base64;
import android.util.Log;

/**
 * Created by dfqin on 2017/4/7.
 */

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

    public static String getSign(String data) {
        return getSign(BaseApplication.getInstance(), data);
    }

    public static String getDeviceId() {
        return "deviceId";
    }

    public static String getAppVersion() {
        return BuildConfig.VERSION_NAME;
    }

    public static String getChannel() {
        return "mainli";
    }

    public static void showToast(String tips) {
        Log.i("Mainli", "tips: " + tips);
    }

    private native static byte[] encryptData(Context context, byte[] data);

    private native static byte[] decryptData(Context context, byte[] data);

    private native static String getSign(Context context, String data);

    static {
        System.loadLibrary("Libs");
    }
}
