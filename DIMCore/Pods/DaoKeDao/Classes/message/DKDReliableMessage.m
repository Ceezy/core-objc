//
//  DKDReliableMessage.m
//  DaoKeDao
//
//  Created by Albert Moky on 2018/9/30.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSData+DKD_Encode.h"
#import "NSString+DKD_Encode.h"

#import "DKDReliableMessage.h"

@interface DKDReliableMessage ()

@property (strong, nonatomic) NSData *signature;

@end

@implementation DKDReliableMessage

- (instancetype)initWithData:(const NSData *)content
                encryptedKey:(nullable const NSData *)key
                    envelope:(const DKDEnvelope *)env {
    NSAssert(false, @"DON'T call me");
    NSData *CT = nil;
    self = [self initWithData:content
                    signature:CT
                 encryptedKey:key
                     envelope:env];
    return self;
}

- (instancetype)initWithData:(const NSData *)content
               encryptedKeys:(nullable const DKDEncryptedKeyMap *)keys
                    envelope:(const DKDEnvelope *)env {
    NSAssert(false, @"DON'T call me");
    NSData *CT = nil;
    self = [self initWithData:content
                    signature:CT
                encryptedKeys:keys
                     envelope:env];
    return self;
}

/* designated initializer */
- (instancetype)initWithData:(const NSData *)content
                   signature:(const NSData *)CT
                encryptedKey:(nullable const NSData *)key
                    envelope:(const DKDEnvelope *)env {
    NSAssert(CT, @"signature cannot be empty");
    if (self = [super initWithData:content
                      encryptedKey:key
                          envelope:env]) {
        // signature
        if (CT) {
            [_storeDictionary setObject:[CT dkd_base64Encode] forKey:@"signature"];
            _signature = [CT copy];
        } else {
            _signature = nil;
        }
    }
    return self;
}

/* designated initializer */
- (instancetype)initWithData:(const NSData *)content
                   signature:(const NSData *)CT
               encryptedKeys:(nullable const DKDEncryptedKeyMap *)keys
                    envelope:(const DKDEnvelope *)env {
    NSAssert(CT, @"signature cannot be empty");
    if (self = [super initWithData:content
                     encryptedKeys:keys
                          envelope:env]) {
        // signature
        if (CT) {
            [_storeDictionary setObject:[CT dkd_base64Encode] forKey:@"signature"];
            _signature = [CT copy];
        } else {
            _signature = nil;
        }
    }
    return self;
}

/* designated initializer */
- (instancetype)initWithDictionary:(NSDictionary *)dict {
    if (self = [super initWithDictionary:dict]) {
        // lazy
        _signature = nil;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    DKDReliableMessage *rMsg = [super copyWithZone:zone];
    if (rMsg) {
        rMsg.signature = _signature;
    }
    return rMsg;
}

- (NSData *)signature {
    if (!_signature) {
        NSString *CT = [_storeDictionary objectForKey:@"signature"];
        NSAssert(CT, @"signature cannot be empty");
        _signature = [CT dkd_base64Decode];
    }
    return _signature;
}

@end

#pragma mark -

@implementation DKDReliableMessage (Meta)

- (const NSDictionary *)meta {
    return [_storeDictionary objectForKey:@"meta"];
}

- (void)setMeta:(const NSDictionary *)meta {
    if (meta) {
        [_storeDictionary setObject:meta forKey:@"meta"];
    } else {
        [_storeDictionary removeObjectForKey:@"meta"];
    }
}

@end
