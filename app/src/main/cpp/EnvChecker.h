#include <jni.h>
#include "Utils.h"

#ifndef WINANDROID_ENVCHECKER_H
#define WINANDROID_ENVCHECKER_H

class EnvChecker {

public:

    //判断是否合法调用
    __attribute__((visibility ("hidden"))) static bool isValid(JNIEnv* env, jobject context);
    __attribute__((visibility ("hidden"))) static jstring  getSign(JNIEnv* env, jobject context, BaseClasses classes);

private:
    __attribute__((visibility ("hidden"))) static jstring getPackageName(JNIEnv* env, jobject context, BaseClasses classes);
    __attribute__((visibility ("hidden"))) static bool checkSign(JNIEnv* env, jobject context, BaseClasses classes);

    __attribute__((visibility ("hidden"))) static bool checkPkgName(JNIEnv* env, jobject context, BaseClasses classes);
};


#endif //WINANDROID_ENVCHECKER_H
