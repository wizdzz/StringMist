#include <jni.h>
#include <string>
#include "blowfish.h"


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_wizd_usegradleplugin_NativeInterface_a(JNIEnv *env, jclass type, jbyteArray in_,
                                                jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);
    int keyLen = env->GetArrayLength(key_);
    int inLen = env->GetArrayLength(in_);

    int newLength = 0;
    BLOWFISH blowfish = BLOWFISH(reinterpret_cast<byte *>(key), keyLen);
    byte *dec = blowfish.Decrypt_CBC(reinterpret_cast<byte *>(in), inLen, &newLength);

    jbyteArray retArr = env->NewByteArray(newLength);
    env->SetByteArrayRegion(retArr, 0, newLength, reinterpret_cast<const jbyte *>(dec));

    delete []dec;
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return retArr;
}
