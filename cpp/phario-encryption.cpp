#include "phario-encryption.h"
#include "aes.h"
#include "hkdf.h"
#include "pbkdf2.h"

#include <sstream>
#include <openssl/rand.h>


// The namespace allows for syntactic sugar around the JSI objects. ex. call: jsi::Function instead of facebook::jsi::Function
using namespace facebook;

void installPharioEncryption(jsi::Runtime& jsiRuntime) {
    auto genRandomBytes = jsi::Function::createFromHostFunction(
                                                                jsiRuntime,
                                                                jsi::PropNameID::forAscii(jsiRuntime, "secureGenRandomBytes"),
                                                                0,
                                                                [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
                                                                    if (!arguments[0].isNumber()) {
                                                                        jsi::detail::throwJSError(runtime, "First argument should be a number!");
                                                                    }
                                                                    
                                                                    int ouput_size = arguments[0].getNumber();
                                                                    uint8_t *output = new uint8_t[ouput_size];
                                                                    
                                                                    if (!RAND_bytes(output, ouput_size)) {
                                                                        delete [] output;
                                                                        jsi::detail::throwJSError(runtime, "Could not generate random bytes!");
                                                                    }

                                                                    
                                                                    jsi::Function array_buffer_ctor = runtime.global().getPropertyAsFunction(runtime, "ArrayBuffer");
                                                                    jsi::ArrayBuffer buf = array_buffer_ctor.callAsConstructor(runtime, ouput_size).getObject(runtime).getArrayBuffer(runtime);
                                                                    // It's a shame we have to copy here: see https://github.com/facebook/hermes/pull/419 and https://github.com/facebook/hermes/issues/564.
                                                                    memcpy(buf.data(runtime), output, ouput_size);

                                                                    delete [] output;
                                                                    
                                                                    return buf;
                                                                });
    
    auto hkdf = jsi::Function::createFromHostFunction(
                                                                jsiRuntime,
                                                                jsi::PropNameID::forAscii(jsiRuntime, "hkdf"),
                                                                3,
                                                                [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
                                                                    if (!arguments[0].isObject() || !arguments[1].isObject() || !arguments[2].isObject() || !arguments[3].isNumber()) {
                                                                        jsi::detail::throwJSError(runtime, "Wrong argument passed to hkdf!");
                                                                    }
                                                                    
                                                                    jsi::ArrayBuffer key = arguments[0].getObject(runtime).getArrayBuffer(runtime);
                                                                    jsi::ArrayBuffer salt = arguments[1].getObject(runtime).getArrayBuffer(runtime);
                                                                    jsi::ArrayBuffer info = arguments[2].getObject(runtime).getArrayBuffer(runtime);
                                                                    auto outputSize = arguments[3].getNumber();
                                                                    uint8_t *output = new uint8_t[outputSize];
                                                                
                                                                    HKDF(key.data(runtime), key.size(runtime),
                                                                         salt.data(runtime), salt.size(runtime),
                                                                         info.data(runtime), info.size(runtime),
                                                                         output, outputSize);
                                                                    
                                                                    // Create new ArrayBuffer for output
                                                                    jsi::Function array_buffer_ctor = runtime.global().getPropertyAsFunction(runtime, "ArrayBuffer");
                                                                    jsi::Object o = array_buffer_ctor.callAsConstructor(runtime, (int)outputSize).getObject(runtime);
                                                                    jsi::ArrayBuffer buf = o.getArrayBuffer(runtime);
                                                                    // It's a shame we have to copy here: see https://github.com/facebook/hermes/pull/419 and https://github.com/facebook/hermes/issues/564.
                                                                    memcpy(buf.data(runtime), output, outputSize);
                                                                    
                                                                    delete [] output;
                                                                    
                                                                    return buf;
                                                                });
    
    auto pbkdf2 = jsi::Function::createFromHostFunction(
                                                                jsiRuntime,
                                                                jsi::PropNameID::forAscii(jsiRuntime, "pbkdf2"),
                                                                3,
                                                                [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
                                                                    if (!arguments[0].isObject() || !arguments[1].isObject() || !arguments[2].isNumber() || !arguments[3].isNumber()) {
                                                                        jsi::detail::throwJSError(runtime, "Wrong argument passed to pbkdf2!");
                                                                    }
                                                                    
                                                                    jsi::ArrayBuffer password = arguments[0].getObject(runtime).getArrayBuffer(runtime);
                                                                    jsi::ArrayBuffer salt = arguments[1].getObject(runtime).getArrayBuffer(runtime);
                                                                    double outputSize = arguments[2].getNumber();
                                                                    double rounds = arguments[3].getNumber();

                                                                    uint8_t *output = new uint8_t[outputSize];
                                                                    
                                                                    PBKDF2_HMAC_SHA_256(
                                                                                        password.data(runtime), password.size(runtime),
                                                                                        salt.data(runtime), salt.size(runtime),
                                                                                        rounds, outputSize, output
                                                                                        );
                        
                                                                    
                                                                    // Create new ArrayBuffer for output
                                                                    jsi::Function array_buffer_ctor = runtime.global().getPropertyAsFunction(runtime, "ArrayBuffer");
                                                                    jsi::Object o = array_buffer_ctor.callAsConstructor(runtime, (int)outputSize).getObject(runtime);
                                                                    jsi::ArrayBuffer buf = o.getArrayBuffer(runtime);
                                                                    // It's a shame we have to copy here: see https://github.com/facebook/hermes/pull/419 and https://github.com/facebook/hermes/issues/564.
                                                                    memcpy(buf.data(runtime), output, outputSize);
                                                                    
                                                                    delete [] output;
                                                                    
                                                                    return buf;
                                                                });

    
    auto encryptAES = jsi::Function::createFromHostFunction(
                                                            jsiRuntime, // JSI runtime instance
                                                            jsi::PropNameID::forAscii(jsiRuntime, "encryptAES"), // Internal function name
                                                            2, // Number of arguments in function
                                                            [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
                                                                // the jsi::Value has a lot of helper methods for you to manipulate the data
                                                                if(!arguments[0].isObject() || !arguments[1].isObject() || !arguments[1].isObject()) {
                                                                    jsi::detail::throwJSError(runtime, "Wrong argument passed to encryptAES");
                                                                }
                                                                
                                                                jsi::ArrayBuffer inputData = arguments[0].getObject(runtime).getArrayBuffer(runtime);
                                                                jsi::ArrayBuffer key = arguments[1].getObject(runtime).getArrayBuffer(runtime);
                                                                jsi::ArrayBuffer iv = arguments[2].getObject(runtime).getArrayBuffer(runtime);
                                                                
                                                                if (key.size(runtime) != 32 || iv.size(runtime) != 16) {
                                                                    jsi::detail::throwJSError(runtime, "Wrong Key or IV size passed to decryptAES");
                                                                }
                                                                
                                                                AESCrypter *crypter = new AESCrypter(key.data(runtime), iv.data(runtime));
                                                                AESCrypterOutput output = crypter->encrypt(inputData.data(runtime), inputData.size(runtime));
                                                                
                                                                // Create new ArrayBuffer for output
                                                                jsi::Function array_buffer_ctor = runtime.global().getPropertyAsFunction(runtime, "ArrayBuffer");
                                                                jsi::Object o = array_buffer_ctor.callAsConstructor(runtime, (int)output.data_len).getObject(runtime);
                                                                jsi::ArrayBuffer buf = o.getArrayBuffer(runtime);
                                                                // It's a shame we have to copy here: see https://github.com/facebook/hermes/pull/419 and https://github.com/facebook/hermes/issues/564.
                                                                memcpy(buf.data(runtime), output.data, output.data_len);
                                                                
                                                                delete [] output.data;
                                                                delete crypter;
                                                                
                                                                return buf;
                                                            });
    
    auto decryptAES = jsi::Function::createFromHostFunction(
                                                            jsiRuntime, // JSI runtime instance
                                                            jsi::PropNameID::forAscii(jsiRuntime, "decryptAES"), // Internal function name
                                                            2, // Number of arguments in function
                                                            [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
                                                                // the jsi::Value has a lot of helper methods for you to manipulate the data
                                                                if(!arguments[0].isObject() || !arguments[1].isObject() || !arguments[1].isObject()) {
                                                                    jsi::detail::throwJSError(runtime, "Wrong argument passed to decryptAES");
                                                                }
                                                                
                                                                jsi::ArrayBuffer inputData = arguments[0].getObject(runtime).getArrayBuffer(runtime);
                                                                jsi::ArrayBuffer key = arguments[1].getObject(runtime).getArrayBuffer(runtime);
                                                                jsi::ArrayBuffer iv = arguments[2].getObject(runtime).getArrayBuffer(runtime);
                                                                
                                                                if (key.size(runtime) != 32 || iv.size(runtime) != 16) {
                                                                    jsi::detail::throwJSError(runtime, "Wrong Key or IV size passed to decryptAES");
                                                                }
                                                                
                                                                AESCrypter *crypter = new AESCrypter(key.data(runtime), iv.data(runtime));
                                                                AESCrypterOutput output = crypter->decrypt(inputData.data(runtime), inputData.size(runtime));
                                                                
                                                                // Create new ArrayBuffer for output
                                                                jsi::Function array_buffer_ctor = runtime.global().getPropertyAsFunction(runtime, "ArrayBuffer");
                                                                jsi::Object o = array_buffer_ctor.callAsConstructor(runtime, (int)output.data_len).getObject(runtime);
                                                                jsi::ArrayBuffer buf = o.getArrayBuffer(runtime);
                                                                // It's a shame we have to copy here: see https://github.com/facebook/hermes/pull/419 and https://github.com/facebook/hermes/issues/564.
                                                                memcpy(buf.data(runtime), output.data, output.data_len);
                                                                
                                                                delete [] output.data;
                                                                delete crypter;
                                                                
                                                                return buf;
                                                            });

    
    // Registers the function on the global object
    jsiRuntime.global().setProperty(jsiRuntime, "encryptAES", std::move(encryptAES));
    jsiRuntime.global().setProperty(jsiRuntime, "decryptAES", std::move(decryptAES));
    jsiRuntime.global().setProperty(jsiRuntime, "secureGenRandomBytes", std::move(genRandomBytes));
    jsiRuntime.global().setProperty(jsiRuntime, "hkdf", std::move(hkdf));
    jsiRuntime.global().setProperty(jsiRuntime, "pbkdf2", std::move(pbkdf2));
}

void cleanUpPharioEncryption() {
    // intentionally left blank
}

