//
//  DKDMessage.h
//  DaoKeDao
//
//  Created by Albert Moky on 2018/10/20.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "DKDDictionary.h"

NS_ASSUME_NONNULL_BEGIN

@class DKDEnvelope;

@protocol DKDMessageDelegate <NSObject>
@end

/**
 *  Common Message
 *
 *      data format: {
 *          //-- envelope
 *          sender   : "moki@xxx",
 *          receiver : "hulk@yyy",
 *          time     : 123,
 *          //-- others
 *          ...
 *      }
 */
@interface DKDMessage : DKDDictionary

@property (readonly, strong, nonatomic) DKDEnvelope *envelope;

// delegate to transform message
@property (weak, nonatomic, nullable) __kindof id<DKDMessageDelegate> delegate;

+ (instancetype)messageWithMessage:(id)msg;

- (instancetype)initWithSender:(const NSString *)from
                      receiver:(const NSString *)to
                          time:(nullable const NSDate *)time;

- (instancetype)initWithEnvelope:(const DKDEnvelope *)env
NS_DESIGNATED_INITIALIZER;

- (instancetype)initWithDictionary:(NSDictionary *)dict
NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
