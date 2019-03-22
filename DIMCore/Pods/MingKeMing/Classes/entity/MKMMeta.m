//
//  MKMMeta.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/24.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSObject+MKM_JSON.h"
#import "NSString+MKM_Decode.h"
#import "NSData+MKM_Crypto.h"

#import "MKMPublicKey.h"
#import "MKMPrivateKey.h"

#import "MKMID.h"

#import "MKMMeta.h"

typedef NS_ENUM(u_char, MKMMetaFlag) {
    MKMMetaInit = 0,
    MKMMetaNormal = 1,
    MKMMetaError = 2,
};

@interface MKMMeta ()

@property (nonatomic) NSUInteger version;

@property (strong, nonatomic, nullable) NSString *seed;
@property (strong, nonatomic) MKMPublicKey *key;
@property (strong, nonatomic, nullable) const NSData *fingerprint;

@property (nonatomic) MKMMetaFlag flag;

@end

/**
 Parse dictionary for meta
 
 @param dict - meta info
 @param meta - meta object
 */
static inline void parse_meta_dictionary(const NSDictionary *dict, MKMMeta *meta) {
    // version
    NSNumber *ver = [dict objectForKey:@"version"];
    NSUInteger version = [ver unsignedIntegerValue];
    assert(ver);
    // public key
    NSDictionary *key = [dict objectForKey:@"key"];
    MKMPublicKey *PK = [MKMPublicKey keyWithKey:key];
    assert(PK);
    
    // init
    meta.version = 0;
    meta.key = nil;
    meta.seed = nil;
    meta.fingerprint = nil;
    meta.flag = MKMMetaInit;
    
    switch (version) {
        case MKMMetaVersion_MKM:
        case MKMMetaVersion_ExBTC: {
            // seed
            NSString *seed = [dict objectForKey:@"seed"];
            assert(seed.length > 0);
            // fingerprint
            NSString *fingerprint = [dict objectForKey:@"fingerprint"];
            NSData *CT = [fingerprint mkm_base64Decode];
            assert(CT.length > 0);
            
            if ([PK verify:[seed mkm_data] withSignature:CT]) {
                meta.version = version;
                meta.key = PK;
                meta.seed = seed;
                meta.fingerprint = CT;
                meta.flag = MKMMetaNormal;
            } else {
                assert(false);
                meta.flag = MKMMetaError;
            }
        }
            break;
            
        case MKMMetaVersion_BTC: {
            assert(![dict objectForKey:@"seed"]);
            assert(![dict objectForKey:@"fingerprint"]);
            if (PK.data.length > 0) {
                meta.version = version;
                meta.key = PK;
                meta.fingerprint = PK.data; // use key.data to generate BTC address
                meta.flag = MKMMetaNormal;
            } else {
                assert(false);
                meta.flag = MKMMetaError;
            }
        }
            break;
            
        default: {
            assert(false);
            meta.flag = MKMMetaError;
        }
            break;
    }
}

@implementation MKMMeta

+ (instancetype)metaWithMeta:(id)meta {
    if ([meta isKindOfClass:[MKMMeta class]]) {
        return meta;
    } else if ([meta isKindOfClass:[NSDictionary class]]) {
        return [[self alloc] initWithDictionary:meta];
    } else if ([meta isKindOfClass:[NSString class]]) {
        return [[self alloc] initWithJSONString:meta];
    } else {
        NSAssert(!meta, @"unexpected meta: %@", meta);
        return nil;
    }
}

- (instancetype)initWithDictionary:(NSDictionary *)dict {
    if (self = [super initWithDictionary:dict]) {
        // lazy loading
        //      this designated initializer will be call by 'copyWithZone:', so
        //      it's better to use lazy loading here.
        _version = 0;
        _seed = nil;
        _key = nil;
        _fingerprint = nil;
        _flag = MKMMetaInit;
    }
    return self;
}

- (instancetype)initWithVersion:(NSUInteger)version
                           seed:(const NSString *)name
                      publicKey:(const MKMPublicKey *)PK
                    fingerprint:(const NSData *)CT {
    NSAssert(name.length > 0, @"meta.seed cannot be empty");
    NSAssert(PK, @"meta.key cannot be empty");
    NSAssert(CT.length > 0, @"meta.fingerprint cannot be empty");
    
    NSDictionary *dict = @{@"version"    :@(version),
                           @"seed"       :name,
                           @"key"        :PK,
                           @"fingerprint":[CT mkm_base64Encode],
                           };
    if (self = [super initWithDictionary:dict]) {
        if (version != MKMMetaVersion_MKM && version != MKMMetaVersion_ExBTC) {
            NSAssert(false, @"meta version error");
            _flag = MKMMetaError;
        } else if ([PK verify:[name mkm_data] withSignature:CT]) {
            _flag = MKMMetaNormal;
        } else {
            _flag = MKMMetaError;
        }
        if (_flag == MKMMetaNormal) {
            _version = version;
            _key = [_storeDictionary objectForKey:@"key"];
            _seed = [_storeDictionary objectForKey:@"seed"];
            _fingerprint = CT;
        } else {
            _version = 0;
            _key = nil;
            _seed = nil;
            _fingerprint = nil;
        }
    }
    return self;
}

- (instancetype)initWithVersion:(NSUInteger)version
                           seed:(const NSString *)name
                     privateKey:(const MKMPrivateKey *)SK
                      publicKey:(const MKMPublicKey *)PK {
    if (PK) {
        NSAssert([PK isMatch:SK], @"PK must match SK");
    } else {
        PK = [SK publicKey];
    }
    NSData *CT = [SK sign:[name mkm_data]];
    return [self initWithVersion:version seed:name publicKey:PK fingerprint:CT];
}

- (instancetype)initWithPublicKey:(const MKMPublicKey *)PK {
    NSAssert(PK, @"meta.key cannot be empty");
    NSUInteger version = MKMMetaVersion_BTC;
    
    NSDictionary *dict = @{@"version"    :@(version),
                           @"key"        :PK,
                           };
    if (self = [super initWithDictionary:dict]) {
        if (PK.data.length > 0) {
            _version = version;
            _key = [_storeDictionary objectForKey:@"key"];
            _seed = nil;
            _fingerprint = PK.data; // use key.data to generate BTC address
            _flag = MKMMetaNormal;
        } else {
            _version = 0;
            _key = nil;
            _seed = nil;
            _fingerprint = nil;
            _flag = MKMMetaError;
        }
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    MKMMeta *meta = [super copyWithZone:zone];
    if (meta) {
        meta.version = _version;
        meta.key = _key;
        meta.seed = _seed;
        meta.fingerprint = _fingerprint;
        meta.flag = _flag;
    }
    return meta;
}

- (NSUInteger)version {
    if (_flag == MKMMetaInit) {
        parse_meta_dictionary(_storeDictionary, self);
    }
    return _version;
}

- (MKMPublicKey *)key {
    if (_flag == MKMMetaInit) {
        parse_meta_dictionary(_storeDictionary, self);
    }
    return _key;
}

- (NSString *)seed {
    if (_flag == MKMMetaInit) {
        parse_meta_dictionary(_storeDictionary, self);
    }
    return _seed;
}

- (const NSData *)fingerprint {
    if (_flag == MKMMetaInit) {
        parse_meta_dictionary(_storeDictionary, self);
    }
    return _fingerprint;
}

- (BOOL)isValid {
    if (_flag == MKMMetaInit) {
        parse_meta_dictionary(_storeDictionary, self);
    }
    return _flag == MKMMetaNormal;;
}

- (BOOL)matchPublicKey:(const MKMPublicKey *)PK {
    if (![self isValid]) {
        NSAssert(false, @"Invalid meta: %@", _storeDictionary);
        return NO;
    }
    if (_version == MKMMetaVersion_BTC) {
        // ID with BTC address has no username
        // so we can just compare the key.data to check matching
        return [PK.data isEqual:_key.data];
    }
    if ([PK isEqual:_key]) {
        return YES;
    }
    // check whether keys equal by verifying signature
    return [PK verify:[_seed mkm_data] withSignature:_fingerprint];
}

#pragma mark - ID & address

- (BOOL)matchID:(const MKMID *)ID {
    if (![ID isValid]) {
        NSAssert(false, @"Invalid ID: %@", ID);
        return NO;
    }
    const MKMID *str = [self buildIDWithNetworkID:ID.type];
    return [ID isEqual:str];
}

// check: address == btc_address(network, CT)
- (BOOL)matchAddress:(const MKMAddress *)address {
    if (![address isValid]) {
        NSAssert(false, @"Invalid address: %@", address);
        return NO;
    }
    const MKMAddress *addr = [self buildAddressWithNetworkID:address.network];
    return [address isEqual:addr];
}

- (const MKMID *)buildIDWithNetworkID:(MKMNetworkType)type {
    const MKMAddress *addr = [self buildAddressWithNetworkID:type];
    if (!addr) {
        NSAssert(false, @"failed to build ID");
        return nil;
    }
    switch (_version) {
        case MKMMetaVersion_MKM:
        case MKMMetaVersion_ExBTC:
            return [[MKMID alloc] initWithName:_seed address:addr];
            
        case MKMMetaVersion_BTC:
            return [[MKMID alloc] initWithAddress:addr];
            
        default:
            break;
    }
    NSAssert(false, @"meta version error");
    return nil;
}

- (const MKMAddress *)buildAddressWithNetworkID:(MKMNetworkType)type {
    if (![self isValid]) {
        NSAssert(false, @"Invalid meta: %@", _storeDictionary);
        return nil;
    }
    switch (_version) {
        case MKMMetaVersion_MKM:
            return [[MKMAddress alloc] initWithFingerprint:_fingerprint
                                                   network:type];
            
        case MKMMetaVersion_BTC:
        case MKMMetaVersion_ExBTC:
            NSAssert(type == MKMNetwork_BTCMain, @"address type error");
            return [[MKMAddress alloc] initWithKeyData:_key.data
                                               network:type];
            
        default:
            NSAssert(false, @"meta version error: %@", _storeDictionary);
            break;
    }
    return nil;
}

@end
