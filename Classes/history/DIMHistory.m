//
//  DIMHistory.m
//  DIMCore
//
//  Created by Albert Moky on 2018/9/24.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "DIMHistoryBlock.h"

#import "DIMHistory.h"

@interface DIMHistory ()

@property (strong, nonatomic) const DIMID *ID;

@property (strong, nonatomic) NSMutableArray *blocks;

@end

@implementation DIMHistory

+ (instancetype)historyWithHistory:(id)history {
    if ([history isKindOfClass:[DIMHistory class]]) {
        return history;
    } else if ([history isKindOfClass:[NSDictionary class]]) {
        return [[self alloc] initWithDictionary:history];
    } else if ([history isKindOfClass:[NSString class]]) {
        return [[self alloc] initWithJSONString:history];
    } else {
        NSAssert(!history, @"unexpected history: %@", history);
        return nil;
    }
}

- (instancetype)initWithID:(const DIMID *)ID {
    if (self = [self init]) {
        _ID = [ID copy];
        _blocks = nil;
    }
    return self;
}

- (instancetype)initWithDictionary:(NSDictionary *)dict {
    if (self = [super initWithDictionary:dict]) {
        // lazy
        _ID = nil;
        _blocks = nil;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    DIMHistory *history = [super copyWithZone:zone];
    if (history) {
        history.ID = _ID;
        history.blocks = _blocks;
    }
    return history;
}

- (const DIMID *)ID {
    if (!_ID) {
        DIMID *ID = [_storeDictionary objectForKey:@"ID"];
        _ID = [DIMID IDWithID:ID];
    }
    return _ID;
}

- (NSArray *)blocks {
    if (!_blocks) {
        NSMutableArray *mArray = [_storeDictionary objectForKey:@"records"];
        if (!mArray) {
            mArray = [[NSMutableArray alloc] init];
            [_storeDictionary setObject:mArray forKey:@"records"];
        }
        _blocks = mArray;
    }
    return _blocks;
}

- (void)addBlock:(DIMHistoryBlock *)record {
    if (![self.blocks containsObject:record]) {
        [_blocks addObject:record];
    }
}

@end
