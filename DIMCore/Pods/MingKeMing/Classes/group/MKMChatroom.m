//
//  MKMChatroom.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMID.h"

#import "MKMChatroom.h"

@implementation MKMChatroom

- (BOOL)existsAdmin:(const MKMID *)ID {
    if ([self.owner isEqual:ID]) {
        return YES;
    }
    NSInteger count = [_dataSource numberOfAdminsInChatroom:self];
    if (count <= 0) {
        return NO;
    }
    const MKMID *admin;
    while (--count >= 0) {
        admin = [_dataSource chatroom:self adminAtIndex:count];
        if ([ID isEqual:admin]) {
            return YES;
        }
    }
    return NO;
}

@end
