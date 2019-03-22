//
//  MKMContact.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMContact.h"

@implementation MKMContact

/* designated initializer */
- (instancetype)initWithID:(const MKMID *)ID {
    if (self = [super initWithID:ID]) {
        //
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    MKMContact *contact = [super copyWithZone:zone];
    if (contact) {
        //
    }
    return contact;
}

@end
