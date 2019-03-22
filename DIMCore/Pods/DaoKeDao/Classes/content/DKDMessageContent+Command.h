//
//  DKDMessageContent+Command.h
//  DaoKeDao
//
//  Created by Albert Moky on 2018/11/10.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "DKDMessageContent.h"

NS_ASSUME_NONNULL_BEGIN

@interface DKDMessageContent (Command)

@property (readonly, strong, nonatomic) NSString *command;

/**
 *  Command message: {
 *      type : 0x88,
 *      sn   : 123,
 *
 *      command : "...", // command name
 *      extra   : info   // command parameters
 *  }
 */
- (instancetype)initWithCommand:(const NSString *)cmd;

@end

#pragma mark - System Command

// network
#define DKDSystemCommand_Handshake @"handshake"
#define DKDSystemCommand_Broadcast @"broadcast"

// message
#define DKDSystemCommand_Receipt   @"receipt"

// facebook
#define DKDSystemCommand_Meta      @"meta"
#define DKDSystemCommand_Profile   @"profile"

NS_ASSUME_NONNULL_END
