//
//  MKMPublicKey.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/25.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMPrivateKey.h"

#import "MKMRSAPublicKey.h"

#import "MKMPublicKey.h"

@implementation MKMPublicKey

- (instancetype)init {
    NSAssert(false, @"DON'T call me");
    self = [self initWithAlgorithm:ACAlgorithmRSA];
    return self;
}

/* designated initializer */
- (instancetype)initWithDictionary:(NSDictionary *)keyInfo {
    if ([self isMemberOfClass:[MKMPublicKey class]]) {
        // register Public Key Classes
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            // RSA
            [MKMPublicKey registerClass:[MKMRSAPublicKey class] forAlgorithm:ACAlgorithmRSA];
            // ECC
            //...
        });
        
        // create instance by subclass with algorithm
        NSString *algorithm = [keyInfo objectForKey:@"algorithm"];
        //Class clazz = MKMPublicKeyClassFromAlgorithmString(algorithm);
        Class clazz = [[self class] classForAlgorithm:algorithm];
        if (clazz) {
            self = [[clazz alloc] initWithDictionary:keyInfo];
        } else {
            NSAssert(false, @"algorithm not support: %@", algorithm);
            self = nil;
        }
    } else if (self = [super initWithDictionary:keyInfo]) {
        //
    }
    
    return self;
}

- (BOOL)isMatch:(const MKMPrivateKey *)SK {
    // 1. if the SK has the same public key, return YES
    if ([SK.publicKey isEqual:self]) {
        return YES;
    }
    // 2. try to verify the SK's signature
    static const NSString *promise = @"Moky loves May Lee forever!";
    NSData *data = [promise dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signature = [SK sign:data];
    return [self verify:data withSignature:signature];
}

@end

@implementation MKMPublicKey (Runtime)

static NSMutableDictionary<const NSString *, Class> *s_publicKeyClasses = nil;

+ (void)registerClass:(Class)keyClass forAlgorithm:(const NSString *)name {
    NSAssert(name.length > 0, @"algorithm cannot be empty");
    NSAssert(!keyClass || [keyClass isSubclassOfClass:[MKMPublicKey class]],
             @"public key class error: %@", keyClass);
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_publicKeyClasses = [[NSMutableDictionary alloc] init];
    });
    if (keyClass) {
        [s_publicKeyClasses setObject:keyClass forKey:name];
    } else {
        [s_publicKeyClasses removeObjectForKey:name];
    }
}

+ (nullable Class)classForAlgorithm:(const NSString *)name {
    NSAssert(name.length > 0, @"algorithm cannot be empty");
    return [s_publicKeyClasses objectForKey:name];
}

@end

@implementation MKMPublicKey (PersistentStore)

+ (instancetype)loadKeyWithIdentifier:(const NSString *)identifier {
    MKMPublicKey *key = nil;
    
    if ([self isEqual:[MKMPublicKey class]]) {
        NSArray<Class> *keyClasses = [s_publicKeyClasses allValues];
        Class clazz;
        for (clazz in keyClasses) {
            key = [clazz loadKeyWithIdentifier:identifier];
            if (key) {
                break;
            }
        }
    } else {
        NSAssert([self isSubclassOfClass:[MKMPublicKey class]],
                 @"unexpected public key class: %@", self);
        key = [super loadKeyWithIdentifier:identifier];
    }
    
    return key;
}

@end
