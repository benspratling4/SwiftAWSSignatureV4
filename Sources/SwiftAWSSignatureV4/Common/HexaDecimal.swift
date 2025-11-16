//
//  Data+Extensions.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/14/25.
//

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif



extension Data {
	
	public func hexBytes(uppercase:Bool = false)->String {
		map() { String(format: (uppercase) ? "%02X" : "%02x", $0) }
			.reduce("", +)
	}
	
}


extension UInt8 {
	
	var hex:String {
		let lowBits:UInt8 = self & 0x0F
		let highBits:UInt8 = (self >> 4)
		return UInt8.hexChars[Int(highBits)] + UInt8.hexChars[Int(lowBits)]
	}
	
	private static let hexChars:[String] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
}


extension UInt64 {
	
	///
	var bytesAsHex:String {
		
		var bytes:[String] = []
		var tempInt:UInt64 = self
		while tempInt > 0 {
			let lowBits:Int = Int(tempInt % 16)
			bytes.insert(UInt64.hexStrings[lowBits], at:0)
			tempInt = tempInt >> 4
		}
		//for ease of calculating total metadata length, prepend '0's to reach constant length
		while bytes.count < 16 {
			bytes.insert("0", at: 0)
		}
		return bytes.joined()
	}
	
	fileprivate static let hexStrings:[String] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
	
}
