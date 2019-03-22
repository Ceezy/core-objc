//
//  DIMProfileCommand.m
//  DIMCore
//
//  Created by Albert Moky on 2019/2/3.
//  Copyright © 2019 DIM Group. All rights reserved.
//

#import "NSObject+MKM_JSON.h"
#import "NSData+MKM_Crypto.h"
#import "NSString+MKM_Decode.h"

#import "DIMBarrack.h"

#import "DIMProfileCommand.h"

@interface DIMProfileCommand ()

@property (strong, nonatomic, nullable) DIMProfile *profile;
@property (strong, nonatomic, nullable) NSData *signature;

@end

@implementation DIMProfileCommand

- (instancetype)initWithDictionary:(NSDictionary *)dict {
    if (self = [super initWithDictionary:dict]) {
        // lazy
        _profile = nil;
        _signature = nil;
    }
    return self;
}

- (instancetype)initWithID:(const DIMID *)ID
                      meta:(nullable const DIMMeta *)meta
                   profile:(nullable const NSString *)profileString
                 signature:(nullable const NSString *)signatureString {
    if (self = [self initWithCommand:@"profile"]) {
        // ID
        if (ID) {
            [_storeDictionary setObject:ID forKey:@"ID"];
        }
        _ID = nil; // lazy
        // meta
        if (meta) {
            [_storeDictionary setObject:meta forKey:@"meta"];
        }
        _meta = nil; // lazy
        
        // profile
        if (profileString) {
            [_storeDictionary setObject:profileString forKey:@"profile"];
        }
        _profile = nil; // lazy
        // signature
        if (signatureString) {
            [_storeDictionary setObject:signatureString forKey:@"signature"];
        }
        _signature = nil; // lazy
    }
    return self;
}

- (instancetype)initWithID:(const DIMID *)ID
                      meta:(nullable const DIMMeta *)meta
                privateKey:(const DIMPrivateKey *)SK
                   profile:(const DIMProfile *)profile {
    NSString *json = [profile mkm_jsonString];
    NSData *data = [json mkm_data];
    NSData *signature = [SK sign:data];
    NSString *string = [signature mkm_base64Encode];
    return [self initWithID:ID meta:meta profile:json signature:string];
}

- (id)copyWithZone:(NSZone *)zone {
    DIMProfileCommand *command = [super copyWithZone:zone];
    if (command) {
        command.profile = _profile;
        command.signature = _signature;
    }
    return command;
}

- (nullable DIMProfile *)profile {
    if (!_profile) {
        NSString *json = [_storeDictionary objectForKey:@"profile"];
        NSData *signature = [self signature];
        if (json && signature) {
            NSData *data = [json mkm_data];
            DIMPublicKey *PK = DIMPublicKeyForID(self.ID);
            if ([PK verify:data withSignature:signature]) {
                _profile = [DIMProfile profileWithProfile:json];
            }
        }
    }
    return _profile;
}

- (nullable NSData *)signature {
    if (!_signature) {
        NSString *base64 = [_storeDictionary objectForKey:@"signature"];
        _signature = [base64 mkm_base64Decode];
    }
    return _signature;
}

@end
