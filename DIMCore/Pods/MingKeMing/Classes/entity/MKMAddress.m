//
//  MKMAddress.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/25.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSString+MKM_Decode.h"
#import "NSData+MKM_Crypto.h"

#import "MKMAddress.h"

typedef NS_ENUM(u_char, MKMAddressFlag) {
    MKMAddressInit = 0,
    MKMAddressNormal = 1,
    MKMAddressError = 2,
};

@interface MKMAddress ()

@property (nonatomic) MKMNetworkType network;
@property (nonatomic) UInt32 code;

@property (nonatomic) MKMAddressFlag flag;

@end

/**
 Get check code of the address

 @param data - network + hash(CT)
 @return prefix 4 bytes after sha256*2
 */
static inline NSData * check_code(const NSData *data) {
    assert([data length] == 21);
    data = [data mkm_sha256d];
    assert([data length] == 32);
    return [data subdataWithRange:NSMakeRange(0, 4)];
}

/**
 Get user number, which for remembering and searching user

 @param cc - check code
 @return unsigned integer
 */
static inline UInt32 user_number(const NSData *cc) {
    assert([cc length] == 4);
    UInt32 number;
    memcpy(&number, [cc bytes], 4);
    return number;
}

/**
 Parse string with BTC address format
 
 @param string - BTC address format string
 @param address - MKM address
 */
static inline void parse_btc_address(const NSString *string, MKMAddress *address) {
    NSData *data = [string mkm_base58Decode];
    NSUInteger len = [data length];
    if (len == 25) {
        // Network ID
        const char *bytes = [data bytes];
        
        // Check Code
        NSData *prefix = [data subdataWithRange:NSMakeRange(0, len-4)];
        NSData *suffix = [data subdataWithRange:NSMakeRange(len-4, 4)];
        NSData *cc = check_code(prefix);
        
        // isValid
        if ([cc isEqualToData:suffix]) {
            address.network = bytes[0];
            address.code = user_number(cc);
            address.flag = MKMAddressNormal;
        } else {
            assert(false);
            address.network = 0;
            address.code = 0;
            address.flag = MKMAddressError;
        }
    } else {
        // other version ?
        assert(false);
        address.network = 0;
        address.code = 0;
        address.flag = MKMAddressError;
    }
}

@implementation MKMAddress

+ (instancetype)addressWithAddress:(id)addr {
    if ([addr isKindOfClass:[MKMAddress class]]) {
        return addr;
    } else if ([addr isKindOfClass:[NSString class]]) {
        return [[self alloc] initWithString:addr];
    } else {
        NSAssert(!addr, @"unexpected address: %@", addr);
        return nil;
    }
}

- (instancetype)initWithString:(NSString *)aString {
    NSAssert(aString.length >= 15, @"address invalid: %@", aString);
    if (self = [super initWithString:aString]) {
        // lazy loading
        //      this designated initializer will be call by 'copyWithZone:', so
        //      it's better to use lazy loading here.
        _network = 0;
        _code = 0;
        _flag = MKMAddressInit;
    }
    return self;
}

- (instancetype)initWithFingerprint:(const NSData *)CT
                            network:(MKMNetworkType)type
                          algorithm:(NSUInteger)version {
    NSString *string = nil;
    UInt32 code = 0;
    MKMAddressFlag flag = MKMAddressInit;
    if (version == MKMAddressAlgorithm_BTC) {
        /**
         *  BTC address algorithm:
         *      digest     = ripemd160(sha256(fingerprint));
         *      check_code = sha256(sha256(network + digest)).prefix(4);
         *      addr       = base58_encode(network + digest + check_code);
         */
        
        // 1. hash = ripemd160(sha256(CT))
        NSData *hash = [[CT mkm_sha256] mkm_ripemd160];
        // 2. _h = network + hash
        NSMutableData *data;
        data = [[NSMutableData alloc] initWithBytes:&type length:1];
        [data appendData:hash];
        // 3. cc = sha256(sha256(_h)).prefix(4)
        NSData *cc = check_code(data);
        code = user_number(cc);
        // 4. addr = base58_encode(_h + cc)
        [data appendData:cc];
        string = [data mkm_base58Encode];
        
        flag = MKMAddressNormal;
    } else {
        NSAssert(false, @"unsupported version: %lu", version);
        flag = MKMAddressError;
    }
    
    if (self = [super initWithString:string]) {
        _network = type;
        _code = code;
        _flag = flag;
    }
    return self;
}

- (instancetype)initWithFingerprint:(const NSData *)CT
                            network:(MKMNetworkType)type {
    return [self initWithFingerprint:CT
                             network:type
                           algorithm:MKMAddressDefaultAlgorithm];
}

- (instancetype)initWithKeyData:(const NSData *)CT
                        network:(MKMNetworkType)type
                      algorithm:(NSUInteger)version {
    return [self initWithFingerprint:CT
                             network:type
                           algorithm:version];
}

- (instancetype)initWithKeyData:(const NSData *)CT
                        network:(MKMNetworkType)type {
    return [self initWithFingerprint:CT
                             network:type
                           algorithm:MKMAddressDefaultAlgorithm];
}

- (id)copyWithZone:(NSZone *)zone {
    MKMAddress *addr = [super copyWithZone:zone];
    if (addr) {
        addr.network = _network;
        addr.code = _code;
        addr.flag = _flag;
    }
    return addr;
}

- (BOOL)isEqual:(id)object {
    return [_storeString isEqualToString:object];
}

- (MKMNetworkType)network {
    if (_flag == MKMAddressInit) {
        parse_btc_address(_storeString, self);
    }
    return _network;
}

- (UInt32)code {
    if (_flag == MKMAddressInit) {
        parse_btc_address(_storeString, self);
    }
    return _code;
}

- (BOOL)isValid {
    if (_flag == MKMAddressInit) {
        parse_btc_address(_storeString, self);
    }
    return _flag == MKMAddressNormal;
}

@end
