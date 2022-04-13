#include <jsi/jsilib.h>
#include <jsi/jsi.h>

#ifndef phario_encryption_hpp
#define phario_encryption_hpp

using namespace facebook;

void installPharioEncryption(facebook::jsi::Runtime& jsiRuntime);

class JSI_EXPORT PharioEncryptionHostObject: public jsi::HostObject {
public:
    jsi::Value get(jsi::Runtime&, const jsi::PropNameID& name) override;
    std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;
};

#endif

