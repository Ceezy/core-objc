//
//  MKMID.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/24.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSObject+MKM_Compare.h"

#import "MKMID.h"

typedef NS_ENUM(u_char, MKMIDFlag) {
    MKMIDInit = 0,
    MKMIDNormal = 1,
    MKMIDError = 2,
};

@interface MKMID () {
    
    NSString *_terminal;
}

@property (strong, nonatomic, nullable) NSString *name;
@property (strong, nonatomic) const MKMAddress *address;

@property (nonatomic) MKMIDFlag flag;

@end

/**
 Parse string for ID
 
 @param string - ID string
 @param ID - ID object
 */
static inline void parse_id_string(const NSString *string, MKMID *ID) {
    NSString *name = nil;
    MKMAddress *address = nil;
    NSString *terminal = nil;
    
    NSArray *pair;
    
    // get terminal
    pair = [string componentsSeparatedByString:@"/"];
    if (pair.count > 1) {
        assert(pair.count == 2);
        string = pair.firstObject; // drop the tail
        terminal = pair.lastObject;
        assert(terminal.length > 0);
    }
    
    // get name & address
    pair = [string componentsSeparatedByString:@"@"];
    if (pair.count > 1) {
        assert(pair.count == 2);
        name = pair.firstObject;
        assert(name.length > 0);
        address = [[MKMAddress alloc] initWithString:pair.lastObject];
    } else {
        address = [[MKMAddress alloc] initWithString:pair.firstObject];
    }
    
    // isValid
    if ([address isValid]) {
        ID.name = name;
        ID.address = address;
        ID.flag = MKMIDNormal;
        ID.terminal = terminal;
    } else {
        assert(false);
        ID.name = nil;
        ID.address = nil;
        ID.flag = MKMIDError;
        ID.terminal = nil;
    }
}

@implementation MKMID

+ (instancetype)IDWithID:(id)ID {
    if ([ID isKindOfClass:[MKMID class]]) {
        return ID;
    } else if ([ID isKindOfClass:[NSString class]]) {
        return [[self alloc] initWithString:ID];
    } else {
        NSAssert(!ID, @"unexpected ID: %@", ID);
        return nil;
    }
}

- (instancetype)initWithString:(NSString *)aString {
    if (self = [super initWithString:aString]) {
        // lazy loading
        //      this designated initializer will be call by 'copyWithZone:', so
        //      it's better to use lazy loading here.
        _name = nil;
        _address = nil;
        _flag = MKMIDInit;
        _terminal = nil;
    }
    return self;
}

- (instancetype)initWithName:(const NSString *)seed
                     address:(const MKMAddress *)addr {
    NSAssert(seed.length > 0, @"ID name should not be empty");
    NSAssert(addr.isValid, @"ID address invalid: %@", addr);
    
    NSString *str = [NSString stringWithFormat:@"%@@%@", seed, addr];
    if (self = [super initWithString:str]) {
        if ([addr isValid]) {
            _name = [seed copy];
            _address = addr;
            _flag = MKMIDNormal;
            _terminal = nil;
        } else {
            NSAssert(false, @"ID properties error: %@, %@", seed, addr);
            _name = nil;
            _address = nil;
            _flag = MKMIDError;
            _terminal = nil;
        }
    }
    return self;
}

- (instancetype)initWithAddress:(const MKMAddress *)addr {
    NSAssert(addr.isValid, @"ID address invalid: %@", addr);
    
    if (self = [super initWithString:(NSString *)addr]) {
        if ([addr isValid]) {
            _name = nil;
            _address = addr;
            _flag = MKMIDNormal;
            _terminal = nil;
        } else {
            NSAssert(false, @"ID property error: %@", addr);
            _name = nil;
            _address = nil;
            _flag = MKMIDError;
            _terminal = nil;
        }
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    MKMID *ID = [super copyWithZone:zone];
    if (ID) {
        ID.name = _name;
        ID.address = _address;
        ID.flag = _flag;
        ID.terminal = _terminal;
    }
    return ID;
}

- (BOOL)isEqual:(id)object {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    MKMID *ID = [MKMID IDWithID:object];
    // check name
    if (NSStringNotEquals(_name, ID.name)) {
        return NO;
    }
    // compare address
    return [_address isEqual:ID.address];
}

- (NSString *)name {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    return _name;
}

- (const MKMAddress *)address {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    return _address;
}

- (NSString *)terminal {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    return _terminal;
}

- (void)setTerminal:(NSString *)terminal {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    if (NSStringNotEquals(_terminal, terminal)) {
        _terminal = terminal;
        
        // update store string
        NSArray *pair = [_storeString componentsSeparatedByString:@"/"];
        NSAssert(pair.count == 1 || pair.count == 2, @"ID error: %@", _storeString);
        if (terminal.length > 0) {
            NSAssert([terminal rangeOfString:@"/"].location == NSNotFound, @"terminal error: %@", terminal);
            _storeString = [NSString stringWithFormat:@"%@/%@", pair.firstObject, terminal];
        } else if (pair.count > 1) {
            _storeString = pair.firstObject;
        }
    }
}

- (BOOL)isValid {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    return _flag == MKMIDNormal;
}

- (MKMNetworkType)type {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    return _address.network;
}

- (UInt32)number {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    return _address.code;
}

- (instancetype)naked {
    if (_flag == MKMIDInit) {
        parse_id_string(_storeString, self);
    }
    if (_terminal) {
        if (_name) {
            return [[[self class] alloc] initWithName:_name
                                              address:_address];
        } else {
            return [[[self class] alloc] initWithAddress:_address];
        }
    } else {
        return self;
    }
}

@end
