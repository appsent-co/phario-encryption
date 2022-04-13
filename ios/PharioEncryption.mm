#import "PharioEncryption.h"
#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import "phario-encryption.h"

@implementation PharioEncryption

RCT_EXPORT_MODULE()

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install)
{
    NSLog(@"Installing global.pharioEncryptionCreateNewInstance...");
    RCTBridge* bridge = [RCTBridge currentBridge];
    RCTCxxBridge* cxxBridge = (RCTCxxBridge*)bridge;
    if (cxxBridge == nil) {
        return @false;
    }
    
    using namespace facebook;
    
    auto jsiRuntime = (jsi::Runtime*) cxxBridge.runtime;
    if (jsiRuntime == nil) {
        return @false;
    }
    auto& runtime = *jsiRuntime;

    installPharioEncryption(runtime);
    
    return @true;
}

- (void)invalidate {
}

@end
