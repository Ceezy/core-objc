//
//  DKDEnvelope.m
//  DaoKeDao
//
//  Created by Albert Moky on 2018/10/1.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSDate+DKD_Timestamp.h"

#import "DKDEnvelope.h"

@interface DKDEnvelope ()

@property (strong, nonatomic) const NSString *sender;
@property (strong, nonatomic) const NSString *receiver;

@property (strong, nonatomic) NSDate *time;

@end

@implementation DKDEnvelope

+ (instancetype)envelopeWithEnvelope:(id)env {
    if ([env isKindOfClass:[DKDEnvelope class]]) {
        return env;
    } else if ([env isKindOfClass:[NSDictionary class]]) {
        return [[self alloc] initWithDictionary:env];
    } else if ([env isKindOfClass:[NSString class]]) {
        return [[self alloc] initWithJSONString:env];
    } else {
        NSAssert(!env, @"unexpected envelope: %@", env);
        return nil;
    }
}

/* designated initializer */
- (instancetype)initWithSender:(const NSString *)from
                      receiver:(const NSString *)to
                          time:(nullable const NSDate *)time {
    if (!time) {
        // now()
        time = [[NSDate alloc] init];
    }
    NSDictionary *dict = @{@"sender"  :from,
                           @"receiver":to,
                           @"time"    :DKD_NSNumberFromDate(time),
                           };
    if (self = [super initWithDictionary:dict]) {
        _sender = from;
        _receiver = to;
        _time = [time copy];
    }
    return self;
}

/* designated initializer */
- (instancetype)initWithDictionary:(NSDictionary *)dict {
    if (self = [super initWithDictionary:dict]) {
        // lazy
        _sender = nil;
        _receiver = nil;
        _time = nil;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    DKDEnvelope *env = [super copyWithZone:zone];
    if (env) {
        env.sender = _sender;
        env.receiver = _receiver;
        env.time = _time;
    }
    return env;
}

- (const NSString *)sender {
    if (!_sender) {
        _sender = [_storeDictionary objectForKey:@"sender"];
    }
    return _sender;
}

- (const NSString *)receiver {
    if (!_receiver) {
        _receiver = [_storeDictionary objectForKey:@"receiver"];
    }
    return _receiver;
}

- (NSDate *)time {
    if (!_time) {
        NSNumber *timestamp = [_storeDictionary objectForKey:@"time"];
        NSAssert(timestamp, @"time error: %@", _storeDictionary);
        _time = DKD_NSDateFromNumber(timestamp);
    }
    return _time;
}

@end
