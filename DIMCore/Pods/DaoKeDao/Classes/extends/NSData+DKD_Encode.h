//
//  NSData+Crypto.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/26.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (DKD_Encode)

- (NSString *)dkd_base64Encode;

@end

NS_ASSUME_NONNULL_END
