//
//  MKMGroup.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMEntity.h"

NS_ASSUME_NONNULL_BEGIN

@interface MKMGroup : MKMEntity {
    
    const MKMID *_founder;
}

@property (readonly, strong, nonatomic) const MKMID *founder;
@property (readonly, strong, nonatomic) const MKMID *owner;

@property (readonly, copy, nonatomic) NSArray<const MKMID *> *members;

- (BOOL)existsMember:(const MKMID *)ID;

// +create(founder)
// -setName(name)
// -abdicate(member, owner)
// -invite(user, admin)
// -expel(member, admin)
// -join(user)
// -quit(member)

@end

#pragma mark - Group Delegate

@protocol MKMGroupDataSource <MKMEntityDataSource>

/**
 Get members count
 */
- (NSInteger)numberOfMembersInGroup:(const MKMGroup *)group;

/**
 Get member at index
 */
- (const MKMID *)group:(const MKMGroup *)group memberAtIndex:(NSInteger)index;

/**
 Get group founder
 */
- (const MKMID *)founderOfGroup:(const MKMGroup *)group;

/**
 Get group owner
 */
@optional
- (const MKMID *)ownerOfGroup:(const MKMGroup *)group;

@end

@protocol MKMGroupDelegate <NSObject>

/**
 Group factory
 */
- (MKMGroup *)groupWithID:(const MKMID *)ID;

/**
 Add member to group
 */
- (BOOL)group:(const MKMGroup *)group addMember:(const MKMID *)member;

/**
 Remove contact of user
 */
- (BOOL)group:(const MKMGroup *)group removeMember:(const MKMID *)member;

@end

NS_ASSUME_NONNULL_END
