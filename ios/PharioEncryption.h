#import <React/RCTBridgeModule.h>
#import "phario-encryption.h"

@interface PharioEncryption : NSObject <RCTBridgeModule>

@property (nonatomic, assign) BOOL setBridgeOnMainQueue;

@end