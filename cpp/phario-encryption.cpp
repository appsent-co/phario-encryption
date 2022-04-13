#include "phario-encryption.h"
#include "aes.h"
#include "hkdf.h"
#include "pbkdf2.h"

#include <sstream>
#include <openssl/rand.h>


// The namespace allows for syntactic sugar around the JSI objects. ex. call: jsi::Function instead of facebook::jsi::Function
using namespace facebook;

std::vector<jsi::PropNameID> PharioEncryptionHostObject::getPropertyNames(jsi::Runtime& rt) {
  std::vector<jsi::PropNameID> result;
  result.push_back(jsi::PropNameID::forUtf8(rt, std::string("secureGenRandomBytes")));
  result.push_back(jsi::PropNameID::forUtf8(rt, std::string("hkdf")));
  result.push_back(jsi::PropNameID::forUtf8(rt, std::string("pbkdf2")));
  result.push_back(jsi::PropNameID::forUtf8(rt, std::string("encryptAES")));
  result.push_back(jsi::PropNameID::forUtf8(rt, std::string("decryptAES")));
  return result;
}

jsi::Value PharioEncryptionHostObject::get(jsi::Runtime& runtime, const jsi::PropNameID& propNameId) {
    auto propName = propNameId.utf8(runtime);
    auto funcName = "PharioEncryption." + propName;
    
    if (propName == "secureGenRandomBytes") {
        return jsi::Function::createFromHostFunction(
                                                     runtime,
                                                     jsi::PropNameID::forAscii(runtime, funcName),
                                                     0,
                                                     [this](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
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
    }
    
    if (propName == "hkdf") {
        return jsi::Function::createFromHostFunction(
                                                     runtime,
                                                     jsi::PropNameID::forAscii(runtime, funcName),
                                                     3,
                                                     [this](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
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
    }
        
        if (propName == "pbkdf2") {
            return jsi::Function::createFromHostFunction(
                                                         runtime,
                                                         jsi::PropNameID::forAscii(runtime, funcName),
                                                         3,
                                                         [this](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
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
        }
    
    if (propName == "encryptAES") {
        return jsi::Function::createFromHostFunction(
                                                      runtime, // JSI runtime instance
                                                      jsi::PropNameID::forAscii(runtime, funcName), // Internal function name
                                                      2, // Number of arguments in function
                                                      [this](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
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
    }
    
    if (propName == "decryptAES") {
        return jsi::Function::createFromHostFunction(
                                                     runtime, // JSI runtime instance
                                                     jsi::PropNameID::forAscii(runtime, funcName), // Internal function name
                                                     2, // Number of arguments in function
                                                     [this](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
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
    }
    
    return jsi::Value::undefined();
}

void installPharioEncryption(jsi::Runtime& jsiRuntime) {
    // Registers the function on the global object
    auto pharioEncryptionCreateNewInstance = jsi::Function::createFromHostFunction(jsiRuntime,
                                                                       jsi::PropNameID::forAscii(jsiRuntime, "pharioEncryptionCreateNewInstance"),
                                                                       0,
                                                                       [](jsi::Runtime& runtime,
                                                                          const jsi::Value& thisValue,
                                                                          const jsi::Value* arguments,
                                                                          size_t count) -> jsi::Value {

                                                                         auto instance = std::make_shared<PharioEncryptionHostObject>();
                                                                         return jsi::Object::createFromHostObject(runtime, instance);
                                                                       });
    jsiRuntime.global().setProperty(jsiRuntime, "pharioEncryptionCreateNewInstance", std::move(pharioEncryptionCreateNewInstance));
}

