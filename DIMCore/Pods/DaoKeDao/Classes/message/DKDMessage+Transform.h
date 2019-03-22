//
//  DKDMessage+Transform.h
//  DaoKeDao
//
//  Created by Albert Moky on 2019/3/15.
//  Copyright © 2019 DIM Group. All rights reserved.
//

#import "DKDInstantMessage.h"
#import "DKDSecureMessage.h"
#import "DKDReliableMessage.h"

NS_ASSUME_NONNULL_BEGIN

/**
 *  Message Transforming
 *  ~~~~~~~~~~~~~~~~~~~~
 *
 *  Instant Message <-> Secure Message <-> Reliable Message
 *  +-------------+     +------------+     +--------------+
 *  |  sender     |     |  sender    |     |  sender      |
 *  |  receiver   |     |  receiver  |     |  receiver    |
 *  |  time       |     |  time      |     |  time        |
 *  |             |     |            |     |              |
 *  |  content    |     |  data      |     |  data        |
 *  +-------------+     |  key/keys  |     |  key/keys    |
 *                      +------------+     |  signature   |
 *                                         +--------------+
 *
 *  Algorithm:
 *  data      = password.encrypt(content)
 *  key       = receiver.public_key.encrypt(password)
 *  signature = sender.private_key.sign(data)
 */

@class DKDMessageContent;

@protocol DKDInstantMessageDelegate <DKDMessageDelegate>

/**
 *  Encrypt the message.content to message.data with symmetric key
 *
 *  @param iMsg - instant message object
 *  @param content - message.content
 *  @param password - symmetric key
 *  @return encrypted message content data
 */
- (nullable NSData *)message:(const DKDInstantMessage *)iMsg
              encryptContent:(const DKDMessageContent *)content
                     withKey:(NSDictionary *)password;

/**
 *  Encrypt the symmetric key with receiver's public key
 *
 *  @param iMsg - instant message object
 *  @param password - symmetric key to be encrypted
 *  @param receiver - receiver ID string
 *  @return encrypted key data
 */
- (nullable NSData *)message:(const DKDInstantMessage *)iMsg
                  encryptKey:(const NSDictionary *)password
                 forReceiver:(const NSString *)receiver;

@end

@protocol DKDSecureMessageDelegate <DKDMessageDelegate>

/**
 *  Decrypt key data to a symmetric key with receiver's private key
 *
 *  @param sMsg - secure message object
 *  @param key - encrypted key data
 *  @param sender - sender/member ID string
 *  @param receiver - receiver ID string
 *  @param group - if it's a group message, offer group ID here
 *  @return symmetric key
 */
- (nullable NSDictionary *)message:(const DKDSecureMessage *)sMsg
                    decryptKeyData:(nullable const NSData *)key
                        fromSender:(const NSString *)sender
                        toReceiver:(const NSString *)receiver
                           inGroup:(nullable const NSString *)group;

/**
 *  Decrypt encrypted data to message.content with symmetric key
 *
 *  @param sMsg - secure message object
 *  @param data - encrypt content data
 *  @param password - symmetric key
 *  @return message content
 */
- (nullable DKDMessageContent *)message:(const DKDSecureMessage *)sMsg
                            decryptData:(const NSData *)data
                                withKey:(const NSDictionary *)password;

/**
 *  Sign the message data(encrypted) with sender's private key
 *
 *  @param sMsg - secure message object
 *  @param data - encrypted message data
 *  @param sender - sender ID string
 *  @return signature
 */
- (nullable NSData *)message:(const DKDSecureMessage *)sMsg
                    signData:(const NSData *)data
                   forSender:(const NSString *)sender;

@end

@protocol DKDReliableMessageDelegate <DKDMessageDelegate>

/**
 *  Verify the message data and signature with sender's public key
 *
 *  @param rMsg - reliable message object
 *  @param data - message data
 *  @param signature - signature for message data
 *  @param sender - sender ID string
 *  @return YES on signature match
 */
- (BOOL)message:(const DKDReliableMessage *)rMsg
     verifyData:(const NSData *)data
  withSignature:(const NSData *)signature
      forSender:(const NSString *)sender;

@end

#pragma mark - Transform

/**
 *  Encrypt the Instant Message to Secure Message
 *
 *    +----------+      +----------+
 *    | sender   |      | sender   |
 *    | receiver |      | receiver |
 *    | time     |  ->  | time     |
 *    |          |      |          |
 *    | content  |      | data     |  1. data = encrypt(content, PW)
 *    +----------+      | key/keys |  2. key  = encrypt(PW, receiver.PK)
 *                      +----------+
 */
@interface DKDInstantMessage (ToSecureMessage)

// personal message
- (nullable DKDSecureMessage *)encryptWithKey:(NSDictionary *)password;

// group message
- (nullable DKDSecureMessage *)encryptWithKey:(NSDictionary *)password
                                   forMembers:(const NSArray<NSString *> *)members;

@end

/**
 *  Decrypt the Secure Message to Instant Message
 *
 *    +----------+      +----------+
 *    | sender   |      | sender   |
 *    | receiver |      | receiver |
 *    | time     |  ->  | time     |
 *    |          |      |          |  1. PW      = decrypt(key, receiver.SK)
 *    | data     |      | content  |  2. content = decrypt(data, PW)
 *    | key/keys |      +----------+
 *    +----------+
 */
@interface DKDSecureMessage (ToInstantMessage)

// personal message
- (nullable DKDInstantMessage *)decrypt;

// group message
- (nullable DKDInstantMessage *)decryptForMember:(const NSString *)ID;

@end

/**
 *  Sign the Secure Message to Reliable Message
 *
 *    +----------+      +----------+
 *    | sender   |      | sender   |
 *    | receiver |      | receiver |
 *    | time     |  ->  | time     |
 *    |          |      |          |
 *    | data     |      | data     |
 *    | key/keys |      | key/keys |
 *    +----------+      | signature|  1. signature = sign(data, sender.SK)
 *                      +----------+
 */
@interface DKDSecureMessage (ToReliableMessage)

- (nullable DKDReliableMessage *)sign;

@end

/**
 *  Verify the Reliable Message to Secure Message
 *
 *    +----------+      +----------+
 *    | sender   |      | sender   |
 *    | receiver |      | receiver |
 *    | time     |  ->  | time     |
 *    |          |      |          |
 *    | data     |      | data     |  1. verify(data, signature, sender.PK)
 *    | key/keys |      | key/keys |
 *    | signature|      +----------+
 *    +----------+
 */
@interface DKDReliableMessage (ToSecureMessage)

- (nullable DKDSecureMessage *)verify;

@end

NS_ASSUME_NONNULL_END
