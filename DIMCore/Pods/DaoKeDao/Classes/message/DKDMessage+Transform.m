//
//  DKDMessage+Transform.m
//  DaoKeDao
//
//  Created by Albert Moky on 2019/3/15.
//  Copyright © 2019 DIM Group. All rights reserved.
//

#import "NSData+DKD_Encode.h"

#import "DKDEnvelope.h"

#import "DKDMessage+Transform.h"

@implementation DKDInstantMessage (ToSecureMessage)

- (nullable NSMutableDictionary *)_prepareDataWithKey:(NSDictionary *)PW {
    DKDMessageContent *content = self.content;
    NSData *data = [self.delegate message:self encryptContent:content withKey:PW];
    if (!data) {
        NSAssert(false, @"failed to encrypt content with key: %@", PW);
        return nil;
    }
    NSMutableDictionary *mDict = [self mutableCopy];
    [mDict removeObjectForKey:@"content"];
    [mDict setObject:[data dkd_base64Encode] forKey:@"data"];
    return mDict;
}

- (nullable DKDSecureMessage *)encryptWithKey:(NSDictionary *)password {
    NSAssert(self.delegate, @"message delegate not set yet");
    // 1. encrypt 'content' to 'data'
    NSMutableDictionary *mDict;
    mDict = [self _prepareDataWithKey:password];
    if (!mDict) {
        return nil;
    }
    
    // 2. encrypt password to 'key'
    const NSString *ID = self.envelope.receiver;
    NSData *key;
    key = [self.delegate message:self encryptKey:password forReceiver:ID];
    if (key) {
        [mDict setObject:[key dkd_base64Encode] forKey:@"key"];
    } else {
        NSLog(@"reused key: %@", password);
    }
    
    // 3. pack message
    return [[DKDSecureMessage alloc] initWithDictionary:mDict];
}

- (nullable DKDSecureMessage *)encryptWithKey:(NSDictionary *)password
                                   forMembers:(const NSArray *)members {
    NSAssert(self.delegate, @"message delegate not set yet");
    // 1. encrypt 'content' to 'data'
    NSMutableDictionary *mDict;
    mDict = [self _prepareDataWithKey:password];
    if (!mDict) {
        return nil;
    }
    members = [members copy];
    
    // 2. encrypt password to 'keys'
    NSMutableDictionary *keyMap;
    keyMap = [[NSMutableDictionary alloc] initWithCapacity:members.count];
    NSData *key;
    for (NSString *ID in members) {
        key = [self.delegate message:self encryptKey:password forReceiver:ID];
        if (key) {
            [keyMap setObject:[key dkd_base64Encode] forKey:ID];
        }
    }
    if (keyMap.count > 0) {
        [mDict setObject:keyMap forKey:@"keys"];
    }
    
    // 3. pack message
    return [[DKDSecureMessage alloc] initWithDictionary:mDict];
}

@end

@implementation DKDSecureMessage (ToInstantMessage)

- (nullable DKDInstantMessage *)decryptWithKeyData:(const NSData *)key
                                              from:(const NSString *)sender
                                                to:(const NSString *)receiver
                                             group:(nullable const NSString *)grp {
    NSAssert(self.delegate, @"message delegate not set yet");
    // 1. decrypt 'key' to symmetric key
    NSDictionary *PW = [self.delegate message:self
                               decryptKeyData:key
                                   fromSender:sender
                                   toReceiver:receiver
                                      inGroup:grp];
    if (!PW) {
        NSLog(@"failed to decrypt symmetric key: %@", self);
        return nil;
    }
    
    // 2. decrypt 'data' to 'content'
    DKDMessageContent *content;
    content = [self.delegate message:self decryptData:self.data withKey:PW];
    if (!content) {
        NSLog(@"failed to decrypt message data: %@", self);
        return nil;
    }
    
    // 3. pack message
    NSMutableDictionary *mDict = [self mutableCopy];
    [mDict removeObjectForKey:@"key"];
    [mDict removeObjectForKey:@"data"];
    [mDict setObject:content forKey:@"content"];
    return [[DKDInstantMessage alloc] initWithDictionary:mDict];
}

- (nullable DKDInstantMessage *)decrypt {
    const NSString *sender = self.envelope.sender;
    const NSString *receiver = self.envelope.receiver;
    const NSString *grp = [self objectForKey:@"group"];
    NSAssert(!grp, @"group message must be decrypted with member ID");
    NSData *key = self.encryptedKey;
    // decrypt
    return [self decryptWithKeyData:key from:sender to:receiver group:grp];
}

- (nullable DKDInstantMessage *)decryptForMember:(const NSString *)member {
    const NSString *sender = self.envelope.sender;
    const NSString *receiver = self.envelope.receiver;
    const NSString *grp = [self objectForKey:@"group"];
    // check group
    if (grp) {
        // if 'group' exists and the 'receiver' is a group ID too,
        // they must be equal; or the 'receiver' must equal to member
        NSAssert([grp isEqual:receiver] || [receiver isEqual:member],
                 @"receiver error: %@", receiver);
        // and the 'group' must not equal to member of course
        NSAssert(![grp isEqual:member],
                 @"member error: %@", member);
    } else {
        // if 'group' not exists, the 'receiver' must be a group ID, and
        // it is not equal to the member of course
        NSAssert(![receiver isEqual:member],
                 @"group error: %@, %@", member, self);
        grp = receiver;
    }
    // check key(s)
    NSData *key = [self.encryptedKeys encryptedKeyForID:member];
    if (!key) {
        // trimmed?
        key = self.encryptedKey;
    }
    // decrypt
    return [self decryptWithKeyData:key from:sender to:member group:grp];
}

@end

@implementation DKDSecureMessage (ToReliableMessage)

- (nullable DKDReliableMessage *)sign {
    const NSString *sender = self.envelope.sender;
    NSData *data = self.data;
    NSAssert(self.delegate, @"message delegate not set yet");
    NSData *signature;
    // sign
    signature = [self.delegate message:self signData:data forSender:sender];
    if (!signature) {
        NSAssert(false, @"failed to sign message: %@", self);
        return nil;
    }
    // pack message
    NSMutableDictionary *mDict = [self mutableCopy];
    [mDict setObject:[signature dkd_base64Encode] forKey:@"signature"];
    return [[DKDReliableMessage alloc] initWithDictionary:mDict];
}

@end

@implementation DKDReliableMessage (ToSecureMessage)

- (nullable DKDSecureMessage *)verify {
    const NSString *sender = self.envelope.sender;
    NSData *data = self.data;
    NSData *signature = self.signature;
    NSAssert(self.delegate, @"message delegate not set yet");
    BOOL correct = [self.delegate message:self
                               verifyData:data
                            withSignature:signature
                                forSender:sender];
    if (!correct) {
        NSAssert(false, @"message signature not match: %@", self);
        return nil;
    }
    NSMutableDictionary *mDict = [self mutableCopy];
    [mDict removeObjectForKey:@"signature"];
    return [[DKDSecureMessage alloc] initWithDictionary:mDict];
}

@end
