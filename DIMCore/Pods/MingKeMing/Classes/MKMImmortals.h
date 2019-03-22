//
//  MKMImmortals.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/11/11.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import <MingKeMing/MingKeMing.h>

NS_ASSUME_NONNULL_BEGIN

// number: 195-183-9394
#define MKM_IMMORTAL_HULK_ID @"hulk@4YeVEN3aUnvC1DNUufCq1bs9zoBSJTzVEj"
// number: 184-083-9527
#define MKM_MONKEY_KING_ID   @"moki@4WDfe3zZ4T7opFSi3iDAKiuTnUHjxmXekk"

/**
 *  Create two immortal accounts for test:
 *
 *      1. Immortal Hulk
 *      2. Monkey King
 */
@interface MKMImmortals : NSObject <MKMMetaDataSource,
                                    MKMEntityDataSource,
                                    MKMAccountDelegate,
                                    MKMUserDataSource,
                                    MKMUserDelegate,
                                    MKMProfileDataSource>

@end

NS_ASSUME_NONNULL_END
