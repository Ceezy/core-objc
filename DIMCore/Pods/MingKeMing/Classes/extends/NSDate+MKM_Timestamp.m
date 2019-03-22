//
//  NSDate+MKM_Timestamp.m
//  MingKeMing
//
//  Created by Albert Moky on 2018/11/15.
//  Copyright © 2018 DIM Group. All rights reserved.
//

#import "NSDate+MKM_Timestamp.h"

NSNumber *MKM_NSNumberFromDate(const NSDate *date) {
    assert(date);
    NSTimeInterval ti = [date timeIntervalSince1970];
    return [[NSNumber alloc] initWithLong:ti];
}

NSDate *MKM_NSDateFromNumber(const NSNumber *timestamp) {
    NSTimeInterval ti = [timestamp doubleValue];
    //assert(ti > 1);
    return [[NSDate alloc] initWithTimeIntervalSince1970:ti];
}
