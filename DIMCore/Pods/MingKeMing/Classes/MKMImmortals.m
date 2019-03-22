//
//  MKMImmortals.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/11/11.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMImmortals.h"

@interface MKMImmortals () {
    
    NSMutableDictionary<const MKMAddress *, const MKMMeta *> *_metaTable;
    NSMutableDictionary<const MKMAddress *, MKMProfile *> *_profileTable;
    
    NSMutableDictionary<const MKMAddress *, MKMUser *> *_userTable;
}

@end

@implementation MKMImmortals

- (instancetype)init {
    if (self = [super init]) {
        _metaTable    = [[NSMutableDictionary alloc] initWithCapacity:2];
        _profileTable = [[NSMutableDictionary alloc] initWithCapacity:2];
        
        _userTable    = [[NSMutableDictionary alloc] initWithCapacity:2];
        
        [self _loadBuiltInAccount:@"mkm_hulk"];
        [self _loadBuiltInAccount:@"mkm_moki"];
    }
    return self;
}

- (void)_loadBuiltInAccount:(NSString *)filename {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];//[NSBundle mainBundle];
    NSString *path = [bundle pathForResource:filename ofType:@"plist"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        NSAssert(false, @"file not exists: %@", path);
        return ;
    }
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    
    // ID
    MKMID *ID = [dict objectForKey:@"ID"];
    ID = [MKMID IDWithID:ID];
    NSAssert(ID.isValid, @"ID error: %@", ID);
    
    // meta
    MKMMeta *meta = [dict objectForKey:@"meta"];
    meta = [MKMMeta metaWithMeta:meta];
    if ([meta matchID:ID]) {
        [_metaTable setObject:meta forKey:ID.address];
        //[MKMFacebook() setMeta:meta forID:ID];
    } else {
        NSAssert(false, @"meta not match ID: %@, %@", ID, meta);
    }
    
    // profile
    MKMProfile *profile = [dict objectForKey:@"profile"];
    profile = [MKMProfile profileWithProfile:profile];
    if (profile) {
        [_profileTable setObject:profile forKey:ID.address];
    } else {
        NSAssert(false, @"profile not fould: %@", dict);
    }
    
    // private key
    MKMPrivateKey *SK = [dict objectForKey:@"privateKey"];
    SK = [MKMPrivateKey keyWithKey:SK];
    if ([meta matchID:ID] && [meta.key isMatch:SK]) {
        // store private key into keychain
        //[SK saveKeyWithIdentifier:ID.address];
    } else {
        NSAssert(false, @"keys not match: %@, meta: %@", SK, meta);
        SK = nil;
    }
    
    // create user
    MKMUser *user = [[MKMUser alloc] initWithID:ID];
    user.dataSource = self;
    //user.privateKey = SK;
    [_userTable setObject:user forKey:ID.address];
    
    NSLog(@"loaded immortal account: %@", [user description]);
}

#pragma mark - Delegates

- (const MKMMeta *)metaForID:(const MKMID *)ID {
    NSAssert([ID isValid], @"ID invalid: %@", ID);
    return [_metaTable objectForKey:ID.address];
}

- (const MKMMeta *)metaForEntity:(const MKMEntity *)entity {
    const MKMID *ID = entity.ID;
    NSAssert([ID isValid], @"entity ID invalid: %@", entity);
    return [_metaTable objectForKey:ID.address];
}

- (NSString *)nameOfEntity:(const MKMEntity *)entity {
    MKMProfile *profile = [self profileForID:entity.ID];
    return profile.name;
}

- (MKMAccount *)accountWithID:(const MKMID *)ID {
    if (MKMNetwork_IsPerson(ID.type)) {
        return [self userWithID:ID];
    } else {
        // not a person account
        NSAssert(MKMNetwork_IsCommunicator(ID.type), @"account ID error: %@", ID);
        return nil;
    }
}

- (NSInteger)numberOfContactsInUser:(const MKMUser *)user {
    //NSLog(@"user %@ get contact count", user);
    if ([_userTable.allKeys containsObject:user.ID.address]) {
        // TODO: get contacts for immortal user
        //...
        return 0;
    } else {
        return 0;
    }
}

- (const MKMID *)user:(const MKMUser *)user contactAtIndex:(NSInteger)index {
    //NSLog(@"user %@ get contact at index: %ld", user, index);
    if ([_userTable.allKeys containsObject:user.ID.address]) {
        // TODO: get contacts for immortal user
        //...
        return nil;
    } else {
        return nil;
    }
}

- (MKMUser *)userWithID:(const MKMID *)ID {
    NSAssert(MKMNetwork_IsPerson(ID.type), @"user ID error: %@", ID);
    return [_userTable objectForKey:ID.address];
}

- (BOOL)user:(const MKMUser *)user addContact:(const MKMID *)contact {
    NSLog(@"user %@ add contact %@", user, contact);
    if ([_userTable.allKeys containsObject:user.ID.address]) {
        // TODO: add contact for immortal user
        //...
        return YES;
    } else {
        return NO;
    }
}

- (BOOL)user:(const MKMUser *)user removeContact:(const MKMID *)contact {
    NSLog(@"user %@ remove contact %@", user, contact);
    if ([_userTable.allKeys containsObject:user.ID.address]) {
        // TODO: remove contact for immortal user
        //...
        return YES;
    } else {
        return NO;
    }
}

- (MKMProfile *)profileForID:(const MKMID *)ID {
    NSAssert(MKMNetwork_IsPerson(ID.type), @"account ID error: %@", ID);
    return [_profileTable objectForKey:ID.address];
}

@end
