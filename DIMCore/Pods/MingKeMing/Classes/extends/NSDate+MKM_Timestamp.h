//
//  NSDate+MKM_Timestamp.h
//  MingKeMing
//
//  Created by Albert Moky on 2018/11/15.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

NSNumber *MKM_NSNumberFromDate(const NSDate *date);

NSDate *MKM_NSDateFromNumber(const NSNumber *timestamp);

NS_ASSUME_NONNULL_END
