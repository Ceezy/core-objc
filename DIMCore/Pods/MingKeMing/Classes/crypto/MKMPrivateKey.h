//
//  MKMPrivateKey.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/9/25.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "MKMAsymmetricKey.h"

NS_ASSUME_NONNULL_BEGIN

@class MKMPublicKey;

/**
 *  AC Private Key
 *
 *      keyInfo format: {
 *          algorithm: "RSA", // ECC, ...
 *          data     : "{BASE64_ENCODE}",
 *          ...
 *      }
 */
@interface MKMPrivateKey : MKMAsymmetricKey <MKMPrivateKey>

/**
 Get public key from private key
 */
@property (readonly, strong, atomic) MKMPublicKey *publicKey;

@end

NS_ASSUME_NONNULL_END
