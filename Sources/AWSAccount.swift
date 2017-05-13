//
//  AWSAccount.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 5/13/17.
//
//

import Foundation
import Cryptor

open class AWSAccount {
	///such as "s3" or "kms"
	public let serviceName:String
	
	public let region:String
	
	public let accessKeyID:String
	
	///as a base-64 string
	public let secretAccessKey:String
	
	public init(serviceName:String, region:String, accessKeyID:String, secretAccessKey:String) {
		self.serviceName = serviceName
		self.region = region
		self.accessKeyID = accessKeyID
		self.secretAccessKey = secretAccessKey
	}
	
	func shortDate(now:DateComponents)->String {
		let month:String = "\(now.month ?? 0)".prepadded("0", length: 2)
		let day:String = "\(now.day ?? 0)".prepadded("0", length: 2)
		return "\(now.year ?? 0)" + month + day
	}
	
	func scope(now:DateComponents)->String {
		return [shortDate(now:now), region, serviceName, "aws4_request"].joined(separator: "/")
	}
	
	func credentialString(now:DateComponents)->String {
		return accessKeyID + "/" + scope(now:now)
	}
	
	static var calendar:Calendar = { ()->(Calendar) in
		var aCalendar = Calendar(identifier: .gregorian)
		//TODO: can we do this on linux?
		aCalendar.locale = Locale(identifier: "en_US")
		aCalendar.timeZone = TimeZone(secondsFromGMT: 0)!
		return aCalendar
	}()
	
	func dateComponents(for date:Date)->DateComponents {
		return AWSAccount.calendar.dateComponents([.year, .month, .day, .weekday, .hour, .minute, .second], from: Date())
	}
	
	///this is a keeper
	func keyForSigning(now:DateComponents)->[UInt8]? {
		guard var keyData:Data = "AWS4".data(using: .utf8)
			,let secretKeyData = secretAccessKey.data(using: .utf8) else { return nil }
		keyData.append(secretKeyData)
		let dateByteArray = CryptoUtils.byteArray(from: shortDate(now:now))
		guard let dateKey:[UInt8] = HMAC(using: HMAC.Algorithm.sha256, key: keyData).update(byteArray: dateByteArray)?.final()
			,let dateRegionKey:[UInt8] = HMAC(using:HMAC.Algorithm.sha256, key: Data(dateKey)).update(byteArray: CryptoUtils.byteArray(from:region))?.final()
			,let dateRegionServiceKey:[UInt8] = HMAC(using:HMAC.Algorithm.sha256, key: Data(dateRegionKey)).update(byteArray: CryptoUtils.byteArray(from:serviceName))?.final() else { return nil }
		return HMAC(using:HMAC.Algorithm.sha256, key: Data(dateRegionServiceKey)).update(byteArray: CryptoUtils.byteArray(from:"aws4_request"))?.final()
	}
	
}
