//
//  MKMPrivateKey.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/25.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMPublicKey.h"

#include "MKMRSAPrivateKey.h"

#import "MKMPrivateKey.h"

@implementation MKMPrivateKey

- (instancetype)init {
    self = [self initWithAlgorithm:ACAlgorithmRSA];
    return self;
}

/* designated initializer */
- (instancetype)initWithDictionary:(NSDictionary *)keyInfo {
    if ([self isMemberOfClass:[MKMPrivateKey class]]) {
        // register Private Key Classes
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            // RSA
            [MKMPrivateKey registerClass:[MKMRSAPrivateKey class] forAlgorithm:ACAlgorithmRSA];
            // ECC
            //...
        });
        
        // create instance by subclass with algorithm
        NSString *algorithm = [keyInfo objectForKey:@"algorithm"];
        //Class clazz = MKMPrivateKeyClassFromAlgorithmString(algorithm);
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

- (BOOL)isEqual:(id)object {
    // 1. if the two key has the same content, return YES
    if ([super isEqual:object]) {
        return YES;
    }
    if ([object isKindOfClass:[MKMPrivateKey class]]) {
        // 2. try to verify by public key
        return [self.publicKey isMatch:(MKMPrivateKey *)object];
    } else {
        return NO;
    }
}

- (MKMPublicKey *)publicKey {
    // implements in subclass
    return nil;
}

@end

@implementation MKMPrivateKey (Runtime)

static NSMutableDictionary<const NSString *, Class> *s_privateKeyClasses = nil;

+ (void)registerClass:(Class)keyClass forAlgorithm:(const NSString *)name {
    NSAssert(name.length > 0, @"algorithm cannot be empty");
    NSAssert(!keyClass || [keyClass isSubclassOfClass:[MKMPrivateKey class]],
             @"private key class error: %@", keyClass);
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_privateKeyClasses = [[NSMutableDictionary alloc] init];
    });
    if (keyClass) {
        [s_privateKeyClasses setObject:keyClass forKey:name];
    } else {
        [s_privateKeyClasses removeObjectForKey:name];
    }
}

+ (nullable Class)classForAlgorithm:(const NSString *)name {
    NSAssert(name.length > 0, @"algorithm cannot be empty");
    return [s_privateKeyClasses objectForKey:name];
}

@end

@implementation MKMPrivateKey (PersistentStore)

+ (instancetype)loadKeyWithIdentifier:(const NSString *)identifier {
    MKMPrivateKey *key = nil;
    
    if ([self isEqual:[MKMPrivateKey class]]) {
        NSArray<Class> *keyClasses = [s_privateKeyClasses allValues];
        Class clazz;
        for (clazz in keyClasses) {
            key = [clazz loadKeyWithIdentifier:identifier];
            if (key) {
                break;
            }
        }
    } else {
        NSAssert([self isSubclassOfClass:[MKMPrivateKey class]],
                 @"unexpected public key class: %@", self);
        key = [super loadKeyWithIdentifier:identifier];
    }
    
    return key;
}

@end
