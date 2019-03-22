//
//  MKMRSAKeyHelper.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/11/25.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMRSAKeyHelper.h"

#pragma mark SecKeyRef vs NSData

static inline SecKeyRef SecKeyRefFromData(const NSData *data,
                                          const NSString *keyClass) {
    // Set the private key query dictionary.
    NSDictionary * dict;
    dict = @{(id)kSecAttrKeyType :(id)kSecAttrKeyTypeRSA,
             (id)kSecAttrKeyClass:keyClass,
             };
    CFErrorRef error = NULL;
    SecKeyRef keyRef = SecKeyCreateWithData((CFDataRef)data,
                                            (CFDictionaryRef)dict,
                                            &error);
    assert(error == NULL);
    return keyRef;
}

SecKeyRef SecKeyRefFromPublicData(const NSData *data) {
    return SecKeyRefFromData(data, (__bridge id)kSecAttrKeyClassPublic);
}

SecKeyRef SecKeyRefFromPrivateData(const NSData *data) {
    return SecKeyRefFromData(data, (__bridge id)kSecAttrKeyClassPrivate);
}

NSData *NSDataFromSecKeyRef(SecKeyRef keyRef) {
    CFErrorRef error = NULL;
    CFDataRef dataRef = SecKeyCopyExternalRepresentation(keyRef, &error);
    assert(error == NULL);
    return (__bridge_transfer NSData *)dataRef;
}

#pragma mark RSA Key Content

static inline NSString *RSAKeyContentFromNSString(const NSString *content,
                                                  const NSString *tag) {
    NSString *sTag, *eTag;
    NSRange spos, epos;
    NSString *key = [content copy];
    
    sTag = [NSString stringWithFormat:@"-----BEGIN RSA %@ KEY-----", tag];
    eTag = [NSString stringWithFormat:@"-----END RSA %@ KEY-----", tag];
    spos = [key rangeOfString:sTag];
    if (spos.length > 0) {
        epos = [key rangeOfString:eTag];
    } else {
        sTag = [NSString stringWithFormat:@"-----BEGIN %@ KEY-----", tag];
        eTag = [NSString stringWithFormat:@"-----END %@ KEY-----", tag];
        spos = [key rangeOfString:sTag];
        epos = [key rangeOfString:eTag];
    }
    
    if (spos.location != NSNotFound && epos.location != NSNotFound) {
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e - s);
        key = [key substringWithRange:range];
    }
    
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    return key;
}

NSString *RSAPublicKeyContentFromNSString(const NSString *content) {
    return RSAKeyContentFromNSString(content, @"PUBLIC");
}

NSString *RSAPrivateKeyContentFromNSString(const NSString *content) {
    return RSAKeyContentFromNSString(content, @"PRIVATE");
}

NSString *NSStringFromRSAPublicKeyContent(const NSString *content) {
    NSMutableString *mString = [[NSMutableString alloc] init];
    [mString appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    NSUInteger pos1, pos2, len = content.length;
    NSString *substr;
    for (pos1 = 0, pos2 = 64; pos1 < len; pos1 = pos2, pos2 += 64) {
        if (pos2 > len) {
            pos2 = len;
        }
        substr = [content substringWithRange:NSMakeRange(pos1, pos2 - pos1)];
        [mString appendString:substr];
        [mString appendString:@"\n"];
    }
    [mString appendString:@"-----END PUBLIC KEY-----\n"];
    return mString;
}

NSString *NSStringFromRSAPrivateKeyContent(const NSString *content) {
    NSMutableString *mString = [[NSMutableString alloc] init];
    [mString appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
    NSUInteger pos1, pos2, len = content.length;
    NSString *substr;
    for (pos1 = 0, pos2 = 64; pos1 < len; pos1 = pos2, pos2 += 64) {
        if (pos2 > len) {
            pos2 = len;
        }
        substr = [content substringWithRange:NSMakeRange(pos1, pos2 - pos1)];
        [mString appendString:substr];
        [mString appendString:@"\n"];
    }
    [mString appendString:@"-----END RSA PRIVATE KEY-----\n"];
    return mString;
}
