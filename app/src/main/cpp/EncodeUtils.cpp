#include <stdint.h>
#include <string>
#include "EncodeUtils.h"
#include "md5.h"
#include "Utils.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "aes.h"
void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);

#ifdef __cplusplus
}
#endif

using namespace std;

__attribute__((visibility ("hidden")))
static string getSalt() {
    string salt = appEnv.deviceID + "appKey" + appEnv.deviceID;
    return salt;
}

__attribute__((visibility ("hidden")))
static void initIv(uint8_t* pIv) {
    uint8_t iv[]  = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCD, 0xDE, 0xAD, 0xBE, 0xEF, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xAA }; // {1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4}
    for (int i = 0; i < KEY_LEN; i++) {
        pIv[i] = iv[i];
    }
}

__attribute__((visibility ("hidden")))
jbyteArray EncodeUtils::encryptData(JNIEnv *env, jbyteArray& data, uint8_t *key) { // key len is 16


    uint8_t iv[KEY_LEN];
    initIv(iv);

//    uint8_t key[KEY_LEN]
//    initKey(key);

    int lenOri = env->GetArrayLength(data); //源数据长度
    jbyte* jData = env->GetByteArrayElements(data, 0);

    uint8_t padding = KEY_LEN - lenOri % KEY_LEN;
    int lenOffset = lenOri + padding;  //用来加密的数据长度必须是16的倍数,不够时补齐

    uint8_t srcData[lenOffset]; //补齐后的源数据
    memcpy(srcData, jData, lenOri);

    for (int i = 0; i < padding; i++) { // PKCS5Padding/PKCS7Padding 填充
        srcData[lenOri + i] = padding;
    }

    uint8_t result[lenOffset];
    result[lenOffset];

    AES128_CBC_encrypt_buffer(result, srcData, lenOffset, key, iv);

    jbyte *by = (jbyte*)result;
    jbyteArray jarray = env->NewByteArray(lenOffset);
    env->SetByteArrayRegion(jarray, 0, lenOffset, by);

    return jarray;

}

__attribute__((visibility ("hidden")))
jstring EncodeUtils::geneSign2(JNIEnv *env) {
    string salt = getSalt();
    string oriSign = salt + "iscc";
    string strSign = MD5(oriSign).toStr();

    char sign2[KEY_LEN + 1] = { 0 };
    memcpy(sign2, strSign.c_str(), KEY_LEN);
    return env->NewStringUTF(sign2);
}
