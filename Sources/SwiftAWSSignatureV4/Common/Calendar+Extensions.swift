//
//  Calendar+Extensions.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/14/25.
//

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif



extension Calendar {
	
	///this is the calendar used for signing
	public static let awsSigV4Calendar:Calendar =  { ()->(Calendar) in
		var aCalendar = Calendar(identifier: .gregorian)
		//TODO: can we do this on linux?
		aCalendar.locale = Locale(identifier: "en_US")
		aCalendar.timeZone = TimeZone(secondsFromGMT: 0)!
		return aCalendar
	}()
	
}


extension DateComponents {
	
	var formattedHTTPDate:String {
		let dayName:String = Calendar.awsSigV4Calendar.shortWeekdaySymbols[(weekday ?? 1) - 1]
		let monthShort:String = Calendar.awsSigV4Calendar.shortMonthSymbols[(month ?? 1) - 1]
		let year:String = "\(year ?? 2015)"
		let day:String = "\(day ?? 1)".prepadded("0", length: 2)
		let hour:String = "\(hour ?? 12)".prepadded("0", length: 2)
		let minute:String = "\(minute ?? 0)".prepadded("0", length: 2)
		let second:String = "\(second ?? 0)".prepadded("0", length: 2)
		return dayName + ", " + day + " " + monthShort + " " + year + " " + hour + ":" + minute + ":" + second + " GMT"
	}
	
	var formattedHTTPBasicDate:String {
		let month:String = "\(month ?? 1)".prepadded("0", length: 2)
		let year:String = "\(year ?? 2015)"
		let day:String = "\(day ?? 1)".prepadded("0", length: 2)
		let hour:String = "\(hour ?? 12)".prepadded("0", length: 2)
		let minute:String = "\(minute ?? 0)".prepadded("0", length: 2)
		let second:String = "\(second ?? 0)".prepadded("0", length: 2)
		return year + month + day + "T" + hour + minute + second + "Z"
	}
	
}


extension Date {
	
	///get the date components from this date necessary for AWS Sig V4 signing
	public var awsSigV4DateComponents:DateComponents {
		Calendar.awsSigV4Calendar.dateComponents([.year, .month, .day, .weekday, .hour, .minute, .second], from: self)
	}
	
}
