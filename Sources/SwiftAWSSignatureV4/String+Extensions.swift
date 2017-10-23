//
//  String+Extensions.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 5/13/17.
//
//

import Foundation

extension String {
	//pads the string to be at least 'length' bytes in .utf8 by pre-pending string
	mutating func prepad(_ string:String, length:Int) {
		while self.lengthOfBytes(using: .utf8) < length {
			self = string + self
		}
	}
	
	func prepadded(_ string:String, length:Int)->String {
		var longer:String = self
		longer.prepad(string, length: length)
		return longer
	}
	
	//assumes the values are in GMT already
	init?(ISO8601Components comps:DateComponents) {
		guard let year:Int = comps.year
			,let month:Int = comps.month
			,let day:Int = comps.day
			,let hour:Int = comps.hour
			,let minute:Int = comps.minute
			,let second:Int = comps.minute
			else { return nil }
		self = "\(year)"
			+ "\(month)".prepadded("0", length: 2)
			+ "\(day)".prepadded("0", length: 2)
			+ "T"
			+ "\(hour)".prepadded("0", length: 2) + ":"
			+ "\(minute)".prepadded("0", length: 2) + ":"
			+ "\(second)".prepadded("0", length: 2)
			+ "Z"
	}
	
	//following amazon's rules
	public func aws_uriEncoded(encodeSlash:Bool)->String? {
		//is utf8 the right encoding?  Amazon's docs assume ascii
		guard let bytes:Data = data(using: .utf8) else { return nil }
		var finalString:String = ""
		for byte in bytes {
			switch byte {
			case 0x2F:  // /
				if encodeSlash {
					finalString.append("%2F")
				} else {
					finalString.append("/")
				}
			case  45, 46, 48...57, 65...90, 95, 97...122, 126:
				finalString.append(String(UnicodeScalar(byte)))
			default:
				finalString.append("%" + byte.hex)
			}
		}
		return finalString
	}
}
