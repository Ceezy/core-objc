//
//  MKMAccount.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/23.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMID.h"
#import "MKMMeta.h"

#import "MKMAccount.h"

@interface MKMAccount ()

@property (readwrite, nonatomic) MKMAccountStatus status;

@end

@implementation MKMAccount

/* designated initializer */
- (instancetype)initWithID:(const MKMID *)ID {
    NSAssert(MKMNetwork_IsCommunicator(ID.type), @"account ID error: %@", ID);
    if (self = [super initWithID:ID]) {
        // account status
        _status = MKMAccountStatusInitialized;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    MKMAccount *account = [super copyWithZone:zone];
    if (account) {
        account.status = _status;
    }
    return account;
}

- (MKMAccountStatus)status {
    if (_status == MKMAccountStatusInitialized) {
        if ([_dataSource respondsToSelector:@selector(statusOfAccount:)]) {
            _status = [_dataSource statusOfAccount:self];
        }
    }
    return _status;
}

- (MKMPublicKey *)publicKey {
    return self.meta.key;
}

@end
