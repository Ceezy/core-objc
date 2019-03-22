//
//  DaoKeDao.h
//  DaoKeDao
//
//  Created by Albert Moky on 2018/10/1.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import <Foundation/Foundation.h>

//! Project version number for DaoKeDao.
FOUNDATION_EXPORT double DaoKeDaoVersionNumber;

//! Project version string for DaoKeDao.
FOUNDATION_EXPORT const unsigned char DaoKeDaoVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <DaoKeDao/PublicHeader.h>

#if !defined(__DAO_KE_DAO__)
#define __DAO_KE_DAO__ 1

// Types
//#import <DaoKeDao/DKDDictionary.h>

// Content
#import <DaoKeDao/DKDMessageContent.h>
#import <DaoKeDao/DKDMessageContent+Text.h>
#import <DaoKeDao/DKDMessageContent+File.h>
#import <DaoKeDao/DKDMessageContent+Image.h>
#import <DaoKeDao/DKDMessageContent+Audio.h>
#import <DaoKeDao/DKDMessageContent+Video.h>
#import <DaoKeDao/DKDMessageContent+Webpage.h>
#import <DaoKeDao/DKDMessageContent+Quote.h>
#import <DaoKeDao/DKDMessageContent+Command.h>
#import <DaoKeDao/DKDMessageContent+History.h>
#import <DaoKeDao/DKDMessageContent+Forward.h>

// Message
#import <DaoKeDao/DKDEnvelope.h>
#import <DaoKeDao/DKDMessage.h>
#import <DaoKeDao/DKDInstantMessage.h>
#import <DaoKeDao/DKDSecureMessage.h>
#import <DaoKeDao/DKDReliableMessage.h>

#import <DaoKeDao/DKDMessage+Transform.h>
#import <DaoKeDao/DKDSecureMessage+Packing.h>

#endif /* ! __DAO_KE_DAO__ */
