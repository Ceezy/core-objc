//
//  MKMEntity.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/26.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMAddress.h"

NS_ASSUME_NONNULL_BEGIN

@class MKMID;
@class MKMMeta;

@protocol MKMEntityDataSource;

@interface MKMEntity : NSObject <NSCopying> {
    
    // convenience for instance accessing
    const MKMID *_ID;
    
    __weak __kindof id<MKMEntityDataSource> _dataSource;
}

@property (readonly, copy, nonatomic) const MKMID *ID;     // name@address

@property (readonly, nonatomic) MKMNetworkType type; // Network ID
@property (readonly, nonatomic) UInt32 number;       // search number

@property (readonly, strong, nonatomic) const MKMMeta *meta;  // meta for entity
@property (readonly, strong, nonatomic) NSString *name; // name or seed

@property (weak, nonatomic) __kindof id<MKMEntityDataSource> dataSource;

- (instancetype)initWithID:(const MKMID *)ID NS_DESIGNATED_INITIALIZER;

@end

#pragma mark - Entity Data Source

@protocol MKMEntityDataSource <NSObject>

/**
 Get meta for entity
 */
- (const MKMMeta *)metaForEntity:(const MKMEntity *)entity;

/**
 Get entity name
 */
- (NSString *)nameOfEntity:(const MKMEntity *)entity;

@end

NS_ASSUME_NONNULL_END
