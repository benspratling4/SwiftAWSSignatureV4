//
//  AWSAccount.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 5/13/17.
//
//

import Foundation
import Crypto


public final class AWSAccount {
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
	
	static let calendar:Calendar = Calendar.awsSigV4Calendar
	
	static func dateComponents(for date:Date)->DateComponents {
		date.awsSigV4DateComponents
	}
	
	///this is a keeper
	func keyForSigning(now:DateComponents)->Data {
		var keyData:Data = Data("AWS4".utf8)
		keyData.append(Data(secretAccessKey.utf8))
		
		var dateHmac = HMAC<SHA256>(key: SymmetricKey(data: keyData))
		dateHmac.update(data: Data(shortDate(now:now).utf8))
		let dateKey = Data(dateHmac.finalize())
		
		var dateRegionHmac = HMAC<SHA256>(key: SymmetricKey(data: dateKey))
		dateRegionHmac.update(data: Data(region.utf8))
		let dateRegionKey = Data(dateRegionHmac.finalize())
		
		var dateRegionServiceHmac = HMAC<SHA256>(key: SymmetricKey(data: dateRegionKey))
		dateRegionServiceHmac.update(data: Data(serviceName.utf8))
		let dateRegionServiceKey = Data(dateRegionServiceHmac.finalize())
		
		var finalHmac = HMAC<SHA256>(key: SymmetricKey(data: dateRegionServiceKey))
		finalHmac.update(data: Data("aws4_request".utf8))
		return Data(finalHmac.finalize())
	}
	
	func stringToSign(canonicalRequest:String, signedHeaders:String, date:DateComponents, headers:[(String, String)])->String {
		var sha = SHA256()
		sha.update(data: Data(canonicalRequest.utf8))
		let hexHash:String = Data(sha.finalize()).hexBytes()
		let timeString:String = date.formattedHTTPBasicDate
		return "AWS4-HMAC-SHA256\n" + timeString + "\n" + scope(now: date) + "\n" + hexHash
	}
	
	func signature(canonicalRequest:String, signedHeaders:String, date:DateComponents, headers:[(String, String)], signingKey:Data)throws->String {
		let stringForSigning = stringToSign(
			canonicalRequest: canonicalRequest,
			signedHeaders: signedHeaders,
			date: date,
			headers: headers
		)
		var signature = HMAC<SHA256>(key: SymmetricKey(data: Data(signingKey)))
		signature.update(data: Data(stringForSigning.utf8))
		return Data(signature.finalize()).hexBytes()
	}
	
	func newAuthHeaderValue(canonicalRequest:String, signedHeaders:String, date:DateComponents, headers:[(String, String)])throws->String {
		let signingKey = keyForSigning(now:date)
		let signatureHex = try signature(
			canonicalRequest: canonicalRequest,
			signedHeaders: signedHeaders,
			date: date,
			headers: headers,
			signingKey:signingKey
		)
		return "AWS4-HMAC-SHA256 Credential=\(credentialString(now:date)),SignedHeaders=\(signedHeaders),Signature=\(signatureHex)"
	}
	
	
}


public struct AWSService {
	
	///such as "s3" or "kms"
	public let serviceName:String
	
	///like "us-east-1"
	public let region:String
	
	public init(serviceName:String, region:String) {
		self.serviceName = serviceName
		self.region = region
	}
	
}
