//
//  NSObject+DKD_JSON.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSObject (DKD_JSON)

- (NSData *)dkd_jsonData;
- (NSString *)dkd_jsonString;

@end

@interface NSString (DKD_Convert)

- (NSData *)dkd_data;

@end

@interface NSData (DKD_Convert)

- (NSString *)dkd_UTF8String;

@end

@interface NSData (DKD_JSON)

- (NSString *)dkd_jsonString;
- (NSArray *)dkd_jsonArray;
- (NSDictionary *)dkd_jsonDictionary;

- (NSMutableArray *)dkd_jsonMutableArray;
- (NSMutableDictionary *)dkd_jsonMutableDictionary;

@end

NS_ASSUME_NONNULL_END
