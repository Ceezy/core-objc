//
//  NSObject+JsON.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSObject+DKD_JSON.h"

@implementation NSObject (DKD_JSON)

- (NSData *)dkd_jsonData {
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

- (NSString *)dkd_jsonString {
    return [[self dkd_jsonData] dkd_UTF8String];
}

@end

@implementation NSString (DKD_Convert)

- (NSData *)dkd_data {
    return [self dataUsingEncoding:NSUTF8StringEncoding];
}

@end

@implementation NSData (DKD_Convert)

- (NSString *)dkd_UTF8String {
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

@implementation NSData (DKD_JSON)

- (id)dkd_jsonObject {
    NSError *error = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:self options:NSJSONReadingAllowFragments error:&error];
    NSAssert(!error, @"json error: %@", error);
    return obj;
}

- (id)dkd_jsonMutableContainer {
    NSError *error = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:self options:NSJSONReadingMutableContainers error:&error];
    NSAssert(!error, @"json error: %@", error);
    return obj;
}

- (NSString *)dkd_jsonString {
    return [self dkd_jsonObject];
}

- (NSArray *)dkd_jsonArray {
    return [self dkd_jsonObject];
}

- (NSDictionary *)dkd_jsonDictionary {
    return [self dkd_jsonObject];
}

- (NSMutableArray *)dkd_jsonMutableArray {
    return [self dkd_jsonMutableContainer];
}

- (NSMutableDictionary *)dkd_jsonMutableDictionary {
    return [self dkd_jsonMutableContainer];
}

@end
