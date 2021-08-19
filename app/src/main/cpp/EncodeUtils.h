#include <jni.h>

#ifndef WINANDROID_ENCODEUTILS_H
#define WINANDROID_ENCODEUTILS_H

class EncodeUtils {

public:
    __attribute__((visibility ("hidden"))) static jbyteArray encryptData(JNIEnv *env, jbyteArray& data, uint8_t *key);


    __attribute__((visibility ("hidden"))) static jstring geneSign2(JNIEnv *env);
};


#endif //WINANDROID_ENCODEUTILS_H
