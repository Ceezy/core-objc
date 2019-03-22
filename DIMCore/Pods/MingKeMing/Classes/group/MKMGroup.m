//
//  MKMGroup.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMPublicKey.h"

#import "MKMID.h"
#import "MKMMeta.h"

#import "MKMGroup.h"

@interface MKMGroup ()

@property (strong, nonatomic) const MKMID *founder;

@end

@implementation MKMGroup

/* designated initializer */
- (instancetype)initWithID:(const MKMID *)ID {
    NSAssert(MKMNetwork_IsGroup(ID.type), @"group ID error: %@", ID);
    if (self = [super initWithID:ID]) {
        // lazy
        _founder = nil;
    }
    
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    MKMGroup *social = [super copyWithZone:zone];
    if (social) {
        social.founder = _founder;
    }
    return social;
}

- (const MKMID *)founder {
    if (!_founder) {
        NSAssert(_dataSource, @"group data source not set yet");
        _founder = [_dataSource founderOfGroup:self];
    }
    return _founder;
}

- (const MKMID *)owner {
    const MKMID *ID = nil;
    if ([_dataSource respondsToSelector:@selector(ownerOfGroup:)]) {
        ID = [_dataSource ownerOfGroup:self];
    }
    return ID;
}

- (NSArray<const MKMID *> *)members {
    NSInteger count = [_dataSource numberOfMembersInGroup:self];
    if (count <= 0) {
        return nil;
    }
    NSMutableArray<const MKMID *> *list;
    list = [[NSMutableArray alloc] initWithCapacity:count];
    const MKMID *ID;
    for (NSInteger index = 0; index < count; ++index) {
        ID = [_dataSource group:self memberAtIndex:index];
        [list addObject:ID];
    }
    // check owner position
    const MKMID *owner = self.owner;
    if (owner) {
        NSUInteger pos = [list indexOfObject:owner];
        if (pos == NSNotFound) {
            [list insertObject:owner atIndex:0];
        } else if (pos > 0) {
            [list exchangeObjectAtIndex:pos withObjectAtIndex:0];
        }
    } else {
        NSLog(@"this group %@ has no owner", self.ID);
    }
    return list;
}

- (BOOL)existsMember:(const MKMID *)ID {
    if ([self.owner isEqual:ID]) {
        return YES;
    }
    NSInteger count = [_dataSource numberOfMembersInGroup:self];
    if (count <= 0) {
        return NO;
    }
    const MKMID *member;
    while (--count >= 0) {
        member = [_dataSource group:self memberAtIndex:count];
        if ([ID isEqual:member]) {
            return YES;
        }
    }
    return NO;
}

@end
