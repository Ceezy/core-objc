//
//  MKMAccount.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/23.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMEntity.h"

NS_ASSUME_NONNULL_BEGIN

@class MKMPublicKey;

typedef NS_ENUM(SInt32, MKMAccountStatus) {
    MKMAccountStatusInitialized = 0,
    MKMAccountStatusRegistered = 1,
    MKMAccountStatusDead = -1,
};

@interface MKMAccount : MKMEntity {
    
    MKMAccountStatus _status;
}

@property (readonly, nonatomic) MKMAccountStatus status;

@property (readonly, strong, nonatomic) MKMPublicKey *publicKey;

@end

#pragma mark - Account Delegate

@protocol MKMAccountDataSource <MKMEntityDataSource>

@optional
- (MKMAccountStatus)statusOfAccount:(const MKMAccount *)account;

@end

@protocol MKMAccountDelegate <NSObject>

/**
 Account factory
 */
- (MKMAccount *)accountWithID:(const MKMID *)ID;

@end

NS_ASSUME_NONNULL_END
