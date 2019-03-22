//
//  MKMSymmetricKey.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/30.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMAESKey.h"

#import "MKMSymmetricKey.h"

@implementation MKMSymmetricKey

- (instancetype)init {
    self = [self initWithAlgorithm:SCAlgorithmAES];
    return self;
}

/* designated initializer */
- (instancetype)initWithDictionary:(NSDictionary *)keyInfo {
    if ([self isMemberOfClass:[MKMSymmetricKey class]]) {
        // register Symmetric Key Classes
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            // AES
            [MKMSymmetricKey registerClass:[MKMAESKey class] forAlgorithm:SCAlgorithmAES];
            // DES
            //...
        });
        
        // create instance by subclass with algorithm
        NSString *algorithm = [keyInfo objectForKey:@"algorithm"];
        //Class clazz = MKMSymmetricKeyClassFromAlgorithmString(algorithm);
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

@end

@implementation MKMSymmetricKey (Runtime)

static NSMutableDictionary<const NSString *, Class> *s_symmetricKeyClasses = nil;

+ (void)registerClass:(Class)keyClass forAlgorithm:(const NSString *)name {
    NSAssert(name.length > 0, @"algorithm cannot be empty");
    NSAssert(!keyClass || [keyClass isSubclassOfClass:[MKMSymmetricKey class]],
             @"symmetric key class error: %@", keyClass);
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_symmetricKeyClasses = [[NSMutableDictionary alloc] init];
    });
    if (keyClass) {
        [s_symmetricKeyClasses setObject:keyClass forKey:name];
    } else {
        [s_symmetricKeyClasses removeObjectForKey:name];
    }
}

+ (nullable Class)classForAlgorithm:(const NSString *)name {
    NSAssert(name.length > 0, @"algorithm cannot be empty");
    return [s_symmetricKeyClasses objectForKey:name];
}

@end

@implementation MKMSymmetricKey (PersistentStore)

+ (instancetype)loadKeyWithIdentifier:(const NSString *)identifier {
    MKMSymmetricKey *key = nil;
    
    if ([self isEqual:[MKMSymmetricKey class]]) {
        NSArray<Class> *keyClasses = [s_symmetricKeyClasses allValues];
        Class clazz;
        for (clazz in keyClasses) {
            key = [clazz loadKeyWithIdentifier:identifier];
            if (key) {
                break;
            }
        }
    } else {
        NSAssert([self isSubclassOfClass:[MKMSymmetricKey class]],
                 @"unexpected symmetric key class: %@", self);
        key = [super loadKeyWithIdentifier:identifier];
    }
    
    return key;
}

@end
