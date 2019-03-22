//
//  MKMMember.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/11/1.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMID.h"

#import "MKMMember.h"

@interface MKMMember ()

@property (strong, nonatomic) const MKMID *groupID;

@end

@implementation MKMMember

- (instancetype)initWithID:(const MKMID *)ID {
    //NSAssert(false, @"DON'T call me");
    MKMID *groupID = nil;
    self = [self initWithGroupID:groupID accountID:ID];
    return self;
}

/* designated initializer */
- (instancetype)initWithGroupID:(const MKMID *)groupID
                      accountID:(const MKMID *)ID {
    NSAssert(MKMNetwork_IsCommunicator(ID.type), @"member ID error: %@", ID);
    NSAssert(!groupID || MKMNetwork_IsGroup(groupID.type), @"group ID error: %@", groupID);
    if (self = [super initWithID:ID]) {
        _groupID = [groupID copy];
        _role = MKMMember_Member;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    MKMMember *member = [super copyWithZone:zone];
    if (member) {
        member.groupID = _groupID;
        member.role = _role;
    }
    return member;
}

@end

#pragma mark -

@implementation MKMFounder

- (instancetype)initWithGroupID:(const MKMID *)groupID
                      accountID:(const MKMID *)ID {
    if (self = [super initWithGroupID:groupID accountID:ID]) {
        _role = MKMMember_Founder;
    }
    return self;
}

@end

@implementation MKMOwner

- (instancetype)initWithGroupID:(const MKMID *)groupID
                      accountID:(const MKMID *)ID {
    if (self = [super initWithGroupID:groupID accountID:ID]) {
        _role = MKMMember_Owner;
    }
    return self;
}

@end

@implementation MKMAdmin

- (instancetype)initWithGroupID:(const MKMID *)groupID
                      accountID:(const MKMID *)ID {
    if (self = [super initWithGroupID:groupID accountID:ID]) {
        _role = MKMMember_Admin;
    }
    return self;
}

@end
