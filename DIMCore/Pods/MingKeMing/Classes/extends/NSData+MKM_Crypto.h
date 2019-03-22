//
//  NSData+Crypto.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/26.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (MKM_Encode)

- (NSString *)mkm_hexEncode;

- (NSString *)mkm_base58Encode;
- (NSString *)mkm_base64Encode;

@end

@interface NSData (MKM_Hash)

- (NSData *)mkm_md5;

- (NSData *)mkm_sha1;
- (NSData *)mkm_sha224;
- (NSData *)mkm_sha256;
- (NSData *)mkm_sha384;
- (NSData *)mkm_sha512;

- (NSData *)mkm_sha256d; // sha256(sha256(data))

- (NSData *)mkm_ripemd160;

@end

@interface NSData (MKM_AES)

- (NSData *)mkm_AES256EncryptWithKey:(const NSData *)key
            initializationVector:(nullable const NSData *)iv;

- (NSData *)mkm_AES256DecryptWithKey:(const NSData *)key
            initializationVector:(nullable const NSData *)iv;

@end

NS_ASSUME_NONNULL_END
