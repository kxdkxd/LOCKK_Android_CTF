#include <jni.h>
#include <string>
#include "Utils.h"
#include "EnvChecker.h"
#include "JavaClassesDef.h"
#include "EncodeUtils.h"
#include <sys/ptrace.h>


static jbyteArray encrypt(JNIEnv *env, jclass instance, jobject contextObject, jbyteArray data) {

    if (EnvChecker::isValid(env, contextObject)) {
        jstring sign = EncodeUtils::geneSign2(env);
        return EncodeUtils::encryptData(env, data, (uint8_t*)jstring2String(env, sign).c_str());
    } else {
        showMeg(env, env->NewStringUTF("encryptData非法调用"));
        return data;
    }
}



static JNINativeMethod nMethods[] = {
        { SecureUtil_encryptData_Method, SecureUtil_encryptData_Param, (void*)encrypt }

};

static jobject getGlobalContext(JNIEnv *env)
{

    jclass activityThread = env->FindClass("android/app/ActivityThread");
    jmethodID currentActivityThread = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject at = env->CallStaticObjectMethod(activityThread, currentActivityThread);

    jmethodID getApplication = env->GetMethodID(activityThread, "getApplication", "()Landroid/app/Application;");
    jobject context = env->CallObjectMethod(at, getApplication);
    return context;
}

JNIEXPORT jint JNICALL JNI_OnLoad (JavaVM* vm,void* reserved){

    //防止动态调试
    ptrace(PTRACE_TRACEME, 0, 0, 0);

    JNIEnv* env = NULL;
    jint result = -1;
    if(vm->GetEnv((void**)&env, JNI_VERSION_1_4) != JNI_OK)
        return result;

    baseClasses.contextClass = (jclass)env->NewGlobalRef(env->FindClass("android/content/Context"));
    baseClasses.signatureClass = (jclass)env->NewGlobalRef(env->FindClass("android/content/pm/Signature"));
    baseClasses.packageManagerClass = (jclass)env->NewGlobalRef(env->FindClass("android/content/pm/PackageManager"));
    baseClasses.packageInfoClass = (jclass)env->NewGlobalRef(env->FindClass("android/content/pm/PackageInfo"));
    baseClasses.jniUtilClass = (jclass)env->NewGlobalRef(env->FindClass(SecureUtil_Clz));

    jobject context = getGlobalContext(env);
    initAppEnv(env, context);

    env->RegisterNatives(baseClasses.jniUtilClass, nMethods, sizeof(nMethods) / sizeof(nMethods[0])); // 动态注册JNI方法

    gIsValid = false;

    logV("JNI OnLoaded");

    return JNI_VERSION_1_4;
}