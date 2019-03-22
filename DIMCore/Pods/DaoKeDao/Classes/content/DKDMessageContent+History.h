//
//  DKDMessageContent+History.h
//  DaoKeDao
//
//  Created by Albert Moky on 2019/2/5.
//  Copyright © 2019 DIM Group. All rights reserved.
//

#import "DKDMessageContent+Command.h"

NS_ASSUME_NONNULL_BEGIN

@interface DKDMessageContent (HistoryCommand)

// reuse the 'command' property defined in DKDMessageContent+Command
//@property (readonly, strong, nonatomic) NSString *command;

@property (readonly, strong, nonatomic) NSDate *time;

/**
 *  History command: {
 *      type : 0x89,
 *      sn   : 123,
 *
 *      command : "...", // command name
 *      time    : 0,     // command timestamp
 *      extra   : info   // command parameters
 *  }
 */
- (instancetype)initWithHistoryCommand:(const NSString *)cmd;

@end

#pragma mark - Account history command

// account
#define DKDHistoryCommand_Register  @"register"
#define DKDHistoryCommand_Suicide   @"suicide"

#pragma mark Group history command

// group: founder/owner
#define DKDGroupCommand_Found      @"found"
#define DKDGroupCommand_Abdicate   @"abdicate"
// group: member
#define DKDGroupCommand_Invite     @"invite"
#define DKDGroupCommand_Expel      @"expel"
#define DKDGroupCommand_Join       @"join"
#define DKDGroupCommand_Quit       @"quit"
// group: administrator/assistant
#define DKDGroupCommand_Hire       @"hire"
#define DKDGroupCommand_Fire       @"fire"
#define DKDGroupCommand_Resign     @"resign"

NS_ASSUME_NONNULL_END
