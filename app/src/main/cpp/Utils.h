#ifndef WINANDROID_CONSTANTS_H
#define WINANDROID_CONSTANTS_H


#include <jni.h>
#include <android/log.h>
#include <string>
#include <cstring>
using namespace std;


#define KEY_LEN 16

struct BaseClasses {
    jclass contextClass;
    jclass signatureClass;
    jclass packageManagerClass;
    jclass packageInfoClass;
    jclass jniUtilClass;
};

struct AppEnv {
    string deviceID;
    string appChannel;
    string appVersion;
};

extern BaseClasses baseClasses;
extern AppEnv appEnv;
extern bool gIsValid; //是否合法调用
extern bool isDebug;

#define PACKAGE_FRONT "com."//app packageName 前半部分
#define PACKAGE_END "iscclockk"  // app packageName 后半部分

#define SIGN_FRONT_DEBUG "30820217a0030201" //debug签名的第8至第15位
#define SIGN_END_DEBUG "58b632a885569a63"   //debug签名的倒数第15位至倒数第8位

#define SIGN_FRONT_RELEASE "30820217a0030201" //release签名的第8至第15位
#define SIGN_END_RELEASE   "58b632a885569a63" //release签名的倒数第15位至倒数第8位

#define  LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE, "NTag", __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, "Ntag", __VA_ARGS__)

extern string jstring2String(JNIEnv* env, jstring str);
extern void showMeg(JNIEnv* env, jstring str);
__attribute__((visibility ("hidden"))) extern void initAppEnv(JNIEnv *env, jobject context);

extern void logV(const char* log);
extern void logD(char* log);
extern void logI(char* log);
extern void logW(char* log);
extern void logE(char* log);

#endif //WINANDROID_CONSTANTS_H
