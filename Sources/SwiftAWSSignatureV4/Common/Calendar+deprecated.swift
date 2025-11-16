//
//  Calendar+HTTPDate.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/12/25.
//
import Foundation





extension Calendar {
	
	@available(*, deprecated, renamed: "formattedHTTPDate", message: "Use DateComponents.formattedHTTPDate instead")
	internal func HTTPDate(_ date:DateComponents)->String {
		let dayName:String = AWSAccount.calendar.shortWeekdaySymbols[date.weekday! - 1]
		let monthShort:String = AWSAccount.calendar.shortMonthSymbols[date.month! - 1]
		let year:String = "\(date.year!)"
		let day:String = "\(date.day!)".prepadded("0", length: 2)
		let hour:String = "\(date.hour!)".prepadded("0", length: 2)
		let minute:String = "\(date.minute!)".prepadded("0", length: 2)
		let second:String = "\(date.second!)".prepadded("0", length: 2)
		return dayName + ", " + day + " " + monthShort + " " + year + " " + hour + ":" + minute + ":" + second + " GMT"
	}
	
}

extension DateComponents {
	@available(*, deprecated, renamed: "formattedHTTPBasicDate", message: "Use DateComponents.formattedHTTPBasicDate instead")
	internal func HTTPBasicDate()->String {
		let month:String = "\(month!)".prepadded("0", length: 2)
		let year:String = "\(year!)"
		let day:String = "\(day!)".prepadded("0", length: 2)
		let hour:String = "\(hour!)".prepadded("0", length: 2)
		let minute:String = "\(minute!)".prepadded("0", length: 2)
		let second:String = "\(second!)".prepadded("0", length: 2)
		return year + month + day + "T" + hour + minute + second + "Z"
	}
}

