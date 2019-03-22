//
//  DKDMessageContent+File.m
//  DaoKeDao
//
//  Created by Albert Moky on 2018/11/27.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSData+DKD_Encode.h"
#import "NSString+DKD_Encode.h"

#import "DKDMessageContent+File.h"

@implementation DKDMessageContent (File)

- (instancetype)initWithFileData:(const NSData *)data
                        filename:(nullable const NSString *)name {
    NSAssert(data.length > 0, @"file data cannot be empty");
    if (self = [self initWithType:DKDMessageType_File]) {
        // url or data
        NSAssert(self.delegate, @"message content delegate not set");
        NSURL *url = [self.delegate URLForFileData:data filename:name];
        if (url) {
            [_storeDictionary setObject:url forKey:@"URL"];
        } else if (data) {
            NSString *content = [data dkd_base64Encode];
            [_storeDictionary setObject:content forKey:@"data"];
        }
        
        // filename
        if (name) {
            [_storeDictionary setObject:name forKey:@"filename"];
        }
    }
    return self;
}

- (NSURL *)URL {
    id url = [_storeDictionary objectForKey:@"URL"];
    if ([url isKindOfClass:[NSURL class]]) {
        return url;
    } else if ([url isKindOfClass:[NSString class]]) {
        url = [NSURL URLWithString:url];
        if (url) {
            [_storeDictionary setObject:url forKey:@"URL"];
        } else {
            NSAssert(false, @"URL error: %@", self);
            //[_storeDictionary removeObjectForKey:@"URL"];
        }
        return url;
    } else {
        NSAssert(!url, @"URL error: %@", url);
        return nil;
    }
}

- (NSData *)fileData {
    NSData *data = nil;
    NSString *content = [_storeDictionary objectForKey:@"data"];
    if (content) {
        // decode file data
        data = [content dkd_base64Decode];
    } else {
        // get file data from URL
        NSURL *url = [self URL];
        NSAssert(url, @"URL not found");
        NSAssert(self.delegate, @"message content delegate not set");
        data = [self.delegate dataWithContentsOfURL:url];
    }
    NSAssert(data, @"failed to get file data");
    return data;
}

- (NSString *)filename {
    return [_storeDictionary objectForKey:@"filename"];
}

@end
