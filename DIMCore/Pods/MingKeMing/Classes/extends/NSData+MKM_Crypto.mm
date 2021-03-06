//
//  NSData+Crypto.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/26.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#import "base58.h"
#import "ripemd160.h"

#import "NSObject+MKM_JSON.h"
#import "NSString+MKM_Decode.h"

#import "NSData+MKM_Crypto.h"

@implementation NSData (MKM_Encode)

- (NSString *)mkm_hexEncode {
    NSMutableString *output = nil;
    
    const char *bytes = (const char *)[self bytes];
    NSUInteger len = [self length];
    output = [[NSMutableString alloc] initWithCapacity:(len*2)];
    for (int i = 0; i < len; ++i) {
        [output appendFormat:@"%02x", (unsigned char)bytes[i]];
    }
    
    return output;
}

- (NSString *)mkm_base58Encode {
    NSString *output = nil;
    
    const unsigned char * pbegin = (const unsigned char *)[self bytes];
    const unsigned char * pend = pbegin + [self length];
    std::string str = EncodeBase58(pbegin, pend);
    output = [[NSString alloc] initWithCString:str.c_str()
                                      encoding:NSUTF8StringEncoding];
    
    return output;
}

- (NSString *)mkm_base64Encode {
    NSDataBase64EncodingOptions opt;
    opt = NSDataBase64EncodingEndLineWithCarriageReturn;
    return [self base64EncodedStringWithOptions:opt];
}

@end

@implementation NSData (MKM_Hash)

- (NSData *)mkm_md5 {
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5([self bytes], (CC_LONG)[self length], digest);
    return [[NSData alloc] initWithBytes:digest length:CC_MD5_DIGEST_LENGTH];
}

- (NSData *)mkm_sha1 {
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([self bytes], (CC_LONG)[self length], digest);
    return [[NSData alloc] initWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
}

- (NSData *)mkm_sha224 {
    unsigned char digest[CC_SHA224_DIGEST_LENGTH];
    CC_SHA224([self bytes], (CC_LONG)[self length], digest);
    return [[NSData alloc] initWithBytes:digest length:CC_SHA224_DIGEST_LENGTH];
}

- (NSData *)mkm_sha256 {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([self bytes], (CC_LONG)[self length], digest);
    return [[NSData alloc] initWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
}

- (NSData *)mkm_sha384 {
    unsigned char digest[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384([self bytes], (CC_LONG)[self length], digest);
    return [[NSData alloc] initWithBytes:digest length:CC_SHA384_DIGEST_LENGTH];
}

- (NSData *)mkm_sha512 {
    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512([self bytes], (CC_LONG)[self length], digest);
    return [[NSData alloc] initWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
}

- (NSData *)mkm_sha256d {
    return [[self mkm_sha256] mkm_sha256];
}

- (NSData *)mkm_ripemd160 {
    NSData *output = nil;
    
    unsigned char *buf = (unsigned char *)[self bytes];
    size_t size = [self length];
    size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;;
    unsigned char hash[OUTPUT_SIZE];
    CRIPEMD160().Write(buf, size).Finalize(hash);
    output = [[NSData alloc] initWithBytes:&hash length:OUTPUT_SIZE];
    
    return output;
}

@end

@implementation NSData (MKM_AES)

- (NSData *)mkm_AES256EncryptWithKey:(const NSData *)key
            initializationVector:(nullable const NSData *)iv {
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getBytes:keyPtr length:sizeof(keyPtr)];
//    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          [iv bytes], /* initialization vector (optional) */
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    if (cryptStatus != kCCSuccess) {
        free(buffer); //free the buffer;
        return nil;
    }
    
    //the returned NSData takes ownership of the buffer and will free it on deallocation
    return [[NSData alloc] initWithBytesNoCopy:buffer length:numBytesEncrypted];
}

- (NSData *)mkm_AES256DecryptWithKey:(const NSData *)key
            initializationVector:(nullable const NSData *)iv {
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getBytes:keyPtr length:sizeof(keyPtr)];
//    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          [iv bytes], /* initialization vector (optional) */
                                          [self bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus != kCCSuccess) {
        free(buffer); //free the buffer;
        return nil;
    }
    
    //the returned NSData takes ownership of the buffer and will free it on deallocation
    return [[NSData alloc] initWithBytesNoCopy:buffer length:numBytesDecrypted];
}

@end
