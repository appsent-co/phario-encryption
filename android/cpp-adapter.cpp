#include <jni.h>
#include "phario-encryption.h"

extern "C" JNIEXPORT void JNICALL
Java_com_pharioencryption_PharioEncryptionModule_installPharioEncryption(JNIEnv *env, jclass clazz, jlong jsiPtr)
{
  installPharioEncryption(*reinterpret_cast<facebook::jsi::Runtime *>(jsiPtr));
}
