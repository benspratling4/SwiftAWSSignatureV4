//
//  File.swift
//  
//
//  Created by Ben Spratling on 5/24/23.
//

import Foundation



extension Data {
	
	func hexBytes(uppercase:Bool = false)->String {
		map() { String(format: (uppercase) ? "%02X" : "%02x", $0) }.reduce("", +)
	}
	
}
