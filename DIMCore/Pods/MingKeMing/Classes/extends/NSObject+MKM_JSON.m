//
//  NSObject+MKM_JsON.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSObject+MKM_JSON.h"

@implementation NSObject (MKM_JSON)

- (NSData *)mkm_jsonData {
    NSData *data = nil;
    
    if ([NSJSONSerialization isValidJSONObject:self]) {
        NSError *error = nil;
        data = [NSJSONSerialization dataWithJSONObject:self
                                               options:NSJSONWritingSortedKeys
                                                 error:&error];
        NSAssert(!error, @"json error: %@", error);
    } else {
        NSAssert(false, @"object format not support for json: %@", self);
    }
    
    return data;
}

- (NSString *)mkm_jsonString {
    return [[self mkm_jsonData] mkm_UTF8String];
}

@end

@implementation NSString (MKM_Convert)

- (NSData *)mkm_data {
    return [self dataUsingEncoding:NSUTF8StringEncoding];
}

@end

@implementation NSData (MKM_Convert)

- (NSString *)mkm_UTF8String {
    const unsigned char * bytes = self.bytes;
    NSUInteger length = self.length;
    while (length > 0) {
        if (bytes[length-1] == 0) {
            --length;
        } else {
            break;
        }
    }
    return [[NSString alloc] initWithBytes:bytes length:length encoding:NSUTF8StringEncoding];
}

@end

@implementation NSData (MKM_JSON)

- (id)mkm_jsonObject {
    NSError *error = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:self options:NSJSONReadingAllowFragments error:&error];
    NSAssert(!error, @"json error: %@", error);
    return obj;
}

- (id)mkm_jsonMutableContainer {
    NSError *error = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:self options:NSJSONReadingMutableContainers error:&error];
    NSAssert(!error, @"json error: %@", error);
    return obj;
}

- (NSString *)mkm_jsonString {
    return [self mkm_jsonObject];
}

- (NSArray *)mkm_jsonArray {
    return [self mkm_jsonObject];
}

- (NSDictionary *)mkm_jsonDictionary {
    return [self mkm_jsonObject];
}

- (NSMutableArray *)mkm_jsonMutableArray {
    return [self mkm_jsonMutableContainer];
}

- (NSMutableDictionary *)mkm_jsonMutableDictionary {
    return [self mkm_jsonMutableContainer];
}

@end
