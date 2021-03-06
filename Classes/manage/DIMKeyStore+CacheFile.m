//
//  DIMKeyStore+CacheFile.m
//  DIMCore
//
//  Created by Albert Moky on 2019/1/28.
//  Copyright © 2019 DIM Group. All rights reserved.
//

#import "NSDictionary+MKM_Binary.h"

#import "DIMKeyStore+CacheFile.h"

#define DIM_KEYSTORE_FILENAME @"keystore.plist"

// receiver -> key
typedef NSMutableDictionary<const DIMAddress *, DIMSymmetricKey *> KeyMap;
// sender -> map<receiver, key>
typedef NSMutableDictionary<const DIMAddress *, KeyMap *> KeyTable;

@interface DIMKeyStore ()

@property (strong, nonatomic) KeyTable *KeyTable;

@property (nonatomic, getter=isDirty) BOOL dirty;

@end

@implementation DIMKeyStore (CacheFile)

static NSString *s_directory = nil;

// "Library/Caches/.ks"
- (NSString *)directory {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSArray *paths;
        paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory,
                                                    NSUserDomainMask, YES);
        NSString *dir = paths.firstObject;
        s_directory = [dir stringByAppendingPathComponent:@".ks"];
    });
    return s_directory;
}

- (void)setDirectory:(NSString *)directory {
    s_directory = directory;
}

// "Library/Caches/.ks/{address}/keystore_*.plist"
- (NSString *)_pathWithID:(const DIMID *)ID filename:(NSString *)name {
    NSString *dir = self.directory;
    dir = [dir stringByAppendingPathComponent:(NSString *)ID.address];
    
    // check base directory exists
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dir isDirectory:nil]) {
        NSError *error = nil;
        // make sure directory exists
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES
                       attributes:nil error:&error];
        assert(!error);
    }
    
    return [dir stringByAppendingPathComponent:name];
}

- (BOOL)flush {
    if (!self.dirty) {
        // nothing changed
        return NO;
    }
    const DIMID *ID = self.currentUser.ID;
    if (!ID.isValid) {
        NSAssert(self.currentUser == nil, @"Current user invalid: %@", self.currentUser);
        return NO;
    }
    self.dirty = NO;
    NSString *path = [self _pathWithID:ID filename:DIM_KEYSTORE_FILENAME];
    return [self.KeyTable mkm_writeToBinaryFile:path];
}

- (BOOL)reload {
    const DIMID *ID = self.currentUser.ID;
    if (!ID.isValid) {
        NSAssert(self.currentUser == nil, @"Current user invalid: %@", self.currentUser);
        return NO;
    }
    
    NSString *path = [self _pathWithID:ID filename:DIM_KEYSTORE_FILENAME];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        NSLog(@"keystore file not exists: %@", path);
        return NO;
    }
    
    BOOL changed = NO;
    BOOL isDirty = self.dirty; // save old flag
    
    KeyMap *keyMap;
    DIMAddress *fromAddress, *toAddress;
    DIMSymmetricKey *cipherKey;
    
    NSString *from, *to;
    NSDictionary *keyTableDict = [NSDictionary dictionaryWithContentsOfFile:path];
    NSDictionary *keyMapDict;
    NSDictionary *keyDict;
    for (from in keyTableDict) {
        keyMapDict = [keyTableDict objectForKey:from];
        fromAddress = [DIMAddress addressWithAddress:from];
        keyMap = [self.KeyTable objectForKey:fromAddress];
        if (!keyMap) {
            keyMap = [[KeyMap alloc] init];
            [self.KeyTable setObject:keyMap forKey:fromAddress];
        }
        for (to in keyMapDict) {
            keyDict = [keyMapDict objectForKey:to];
            toAddress = [DIMAddress addressWithAddress:to];
            if ([keyMap objectForKey:toAddress]) {
                // key exists
                continue;
            }
            cipherKey = [DIMSymmetricKey keyWithKey:keyDict];
            changed = YES;
        }
    }
    
    self.dirty = isDirty; // restore the flag
    return changed;
}

@end
