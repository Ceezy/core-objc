//
//  NSDictionary+MKM_Binary.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/11/8.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSDictionary+MKM_Binary.h"

@implementation NSDictionary (MKM_Binary)

- (BOOL)mkm_writeToBinaryFile:(NSString *)path {
    NSData *data;
    NSPropertyListFormat fmt = NSPropertyListBinaryFormat_v1_0;
    NSPropertyListWriteOptions opt = 0;
    NSError *err = nil;
    data = [NSPropertyListSerialization dataWithPropertyList:self
                                                      format:fmt
                                                     options:opt
                                                       error:&err];
    if (err) {
        NSAssert(false, @"serialize failed: %@", err);
        return NO;
    }
    return [data writeToFile:path atomically:YES];
}

@end
