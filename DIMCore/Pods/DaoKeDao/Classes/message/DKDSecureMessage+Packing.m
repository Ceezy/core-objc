//
//  DKDSecureMessage+Packing.m
//  DaoKeDao
//
//  Created by Albert Moky on 2018/12/28.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "DKDEnvelope.h"

#import "DKDSecureMessage+Packing.h"

@implementation DKDSecureMessage (Packing)

- (nullable const NSString *)group {
    return [_storeDictionary objectForKey:@"group"];
}

- (void)setGroup:(const NSString *)group {
    if (group) {
        [_storeDictionary setObject:group forKey:@"group"];
    } else {
        [_storeDictionary removeObjectForKey:@"group"];
    }
}

#pragma mark -

- (NSArray *)splitForMembers:(const NSArray<const NSString *> *)members {
    members = [members copy];
    NSMutableArray *mArray = [[NSMutableArray alloc] initWithCapacity:members.count];
    
    const NSString *receiver = self.envelope.receiver;
    
    NSMutableDictionary *msg;
    msg = [[NSMutableDictionary alloc] initWithDictionary:self];
    [msg setObject:receiver forKey:@"group"];
    
    DKDEncryptedKeyMap *keyMap = self.encryptedKeys;
    
    NSString *base64;
    for (NSString *member in members) {
        // 1. change receiver to the group member
        [msg setObject:member forKey:@"receiver"];
        // 2. get encrypted key
        base64 = [keyMap objectForKey:member];
        if (base64) {
            [msg setObject:base64 forKey:@"key"];
        } else {
            [msg removeObjectForKey:@"key"];
        }
        // 3. repack message
        [mArray addObject:[[[self class] alloc] initWithDictionary:msg]];
    }
    
    return mArray;
}

- (DKDSecureMessage *)trimForMember:(const NSString *)member {
    NSMutableDictionary *mDict = [self mutableCopy];
    
    NSDictionary *keys = [mDict objectForKey:@"keys"];
    NSString *base64 = [keys objectForKey:member];
    if (base64) {
        [mDict setObject:base64 forKey:@"key"];
    }
    [mDict removeObjectForKey:@"keys"];
    
    // repack
    return [[DKDSecureMessage alloc] initWithDictionary:mDict];
}

@end
