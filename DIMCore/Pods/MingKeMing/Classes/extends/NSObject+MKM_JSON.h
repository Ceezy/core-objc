//
//  NSObject+MKM_JsON.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSObject (MKM_JSON)

- (NSData *)mkm_jsonData;
- (NSString *)mkm_jsonString;

@end

@interface NSString (MKM_Convert)

- (NSData *)mkm_data;

@end

@interface NSData (MKM_Convert)

- (NSString *)mkm_UTF8String;

@end

@interface NSData (MKM_JSON)

- (NSString *)mkm_jsonString;
- (NSArray *)mkm_jsonArray;
- (NSDictionary *)mkm_jsonDictionary;

- (NSMutableArray *)mkm_jsonMutableArray;
- (NSMutableDictionary *)mkm_jsonMutableDictionary;

@end

NS_ASSUME_NONNULL_END
