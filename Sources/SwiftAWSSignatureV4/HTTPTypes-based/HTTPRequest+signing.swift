//
//  TestDataExtensionsFile.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/14/25.
//


#if HTTPTypes

///a common
import HTTPTypes

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif

import Crypto




extension HTTPRequest {
	
	
	///make sure you manually add Content-Length before signing
	public func awsSigV4Signed(_ awsAccount:AWSAccount, bodyData:(any DataProtocol)?)throws->HTTPRequest {
		let bodyHash:Data? = bodyData.flatMap { bodyBytes in
			var hash = SHA256()
			hash.update(data: bodyBytes)
			return Data(hash.finalize())
		}
		let date = Date().awsSigV4DateComponents
		return try awsSigV4Signed(awsAccount, bodySha256Hash: bodyHash, date:date)
	}
	
	
	func awsSigV4Signed(_ awsAccount:AWSAccount, bodySha256Hash:Data?, date:DateComponents)throws->HTTPRequest {
		let bodyHashString:String
		if let bodySha256Hash {
			bodyHashString = bodySha256Hash.hexBytes(uppercase: false)
		}
		else {
			bodyHashString = "UNSIGNED-PAYLOAD"
		}
		var requestWithPreAuthheader = try addingPreAuthFields(date: date, bodyHash: bodyHashString)
		let canonicalHeaders = requestWithPreAuthheader.canonicalHeaders
		let signedHeaders = canonicalHeaders
			.map(\.name)
			.joined(separator: ";")
		
		guard let aUrl = self.url
			,let components = URLComponents(url:aUrl, resolvingAgainstBaseURL: false) else {
			//TODO: write me
			fatalError()
		}
		let method = pseudoHeaderFields.method.value
		let requestStringBeforePayload = try components.canonicalRequestBeforePayload(method: method, headers: canonicalHeaders)
		let canonicalRequest:String = requestStringBeforePayload + "\n" + bodyHashString
		
		let authHeaderValue = try awsAccount.newAuthHeaderValue(
			canonicalRequest: canonicalRequest,
			signedHeaders: signedHeaders,
			date: date,
			headers: canonicalHeaders
		)
		requestWithPreAuthheader.headerFields[.authorization] = authHeaderValue
		return requestWithPreAuthheader
	}
	
}


#endif
