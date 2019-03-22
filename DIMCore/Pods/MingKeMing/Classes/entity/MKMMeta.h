//
//  MKMMeta.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/24.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMDictionary.h"

#import "MKMAddress.h"

NS_ASSUME_NONNULL_BEGIN

/**
 *  @enum MKMMetaVersion
 *
 *  @abstract Defined for algorithm that generating address.
 *
 *  @discussion Generate & check ID/Address
 *
 *      MKMMetaVersion_MKM give a seed string first, and sign this seed to get
 *      fingerprint; after that, use the fingerprint to generate address.
 *      This will get a firmly relationship between (username, address & key).
 *
 *      MKMMetaVersion_BTC use the key data to generate address directly.
 *      This can build a BTC address for the entity ID (no username).
 *
 *      MKMMetaVersion_ExBTC use the key data to generate address directly, and
 *      sign the seed to get fingerprint (just for binding username & key).
 *      This can build a BTC address, and bind a username to the entity ID.
 */
#define MKMMetaVersion_MKM    0x01
#define MKMMetaVersion_BTC    0x02
#define MKMMetaVersion_ExBTC  0x03
#define MKMMetaDefaultVersion MKMMetaVersion_MKM

@class MKMPublicKey;
@class MKMPrivateKey;

@class MKMID;

/**
 *  Account/Group Meta data
 *
 *      data format: {
 *          version: 1,          // algorithm version
 *          seed: "moKy",        // user/group name
 *          key: "{public key}", // PK = secp256k1(SK);
 *          fingerprint: "..."   // CT = sign(seed, SK);
 *      }
 *
 *      algorithm:
 *          fingerprint = sign(seed, SK);
 *
 *          CT      = fingerprint; // or key.data for BTC address
 *          hash    = ripemd160(sha256(CT));
 *          code    = sha256(sha256(network + hash)).prefix(4);
 *          address = base58_encode(network + hash + code);
 *          number  = uint(code);
 */
@interface MKMMeta : MKMDictionary

/**
 *  Meta algorithm version
 *
 *      0x01 - username@address
 *      0x02 - btc_address
 *      0x03 - username@btc_address
 */
@property (readonly, nonatomic) NSUInteger version;

/**
 *  Public key
 *
 *      RSA / ECC
 */
@property (readonly, strong, nonatomic) MKMPublicKey *key;

/**
 *  Seed to generate fingerprint
 *
 *      Username / Group-X
 */
@property (readonly, strong, nonatomic, nullable) NSString *seed;

/**
 *  Fingerprint to verify ID and public key
 *
 *      Build: fingerprint = sign(seed, privateKey)
 *      Check: verify(seed, fingerprint, publicKey)
 */
@property (readonly, strong, nonatomic, nullable) const NSData *fingerprint;

@property (readonly, nonatomic, getter=isValid) BOOL valid;

+ (instancetype)metaWithMeta:(id)meta;

/**
 *  Copy meta data
 */
- (instancetype)initWithDictionary:(NSDictionary *)dict;

- (instancetype)initWithVersion:(NSUInteger)version
                           seed:(const NSString *)name
                      publicKey:(const MKMPublicKey *)PK
                    fingerprint:(const NSData *)CT;

/**
 Generate fingerprint, initialize meta data
 
 @param version - meta version for MKM or ExBTC
 @param name - seed for fingerprint
 @param SK - private key to generate fingerprint
 @param PK - public key, which must match the private key
 @return Meta object
 */
- (instancetype)initWithVersion:(NSUInteger)version
                           seed:(const NSString *)name
                     privateKey:(const MKMPrivateKey *)SK
                      publicKey:(nullable const MKMPublicKey *)PK;

/**
 *  For BTC address
 */
- (instancetype)initWithPublicKey:(const MKMPublicKey *)PK;

- (BOOL)matchPublicKey:(const MKMPublicKey *)PK;

#pragma mark - ID & address

- (BOOL)matchID:(const MKMID *)ID;
- (BOOL)matchAddress:(const MKMAddress *)address;

- (const MKMID *)buildIDWithNetworkID:(MKMNetworkType)type;
- (const MKMAddress *)buildAddressWithNetworkID:(MKMNetworkType)type;

@end

#pragma mark - Meta Data Source

@protocol MKMMetaDataSource <NSObject>

/**
 Get meta for ID
 */
- (const MKMMeta *)metaForID:(const MKMID *)ID;

@end

NS_ASSUME_NONNULL_END
