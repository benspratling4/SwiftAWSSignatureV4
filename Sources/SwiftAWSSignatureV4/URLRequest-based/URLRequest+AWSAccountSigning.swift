//
//  AmazonS3.swift
//
//  Created by Ben Spratling on 3/30/17.
//
//

#if Apple

import Foundation
import Dispatch
import Crypto



//Based on http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html


extension URLRequest {
	
	///adds an Authorization header
	/// uses chunking if a chunk size is specified, or if the httpBody is a stream.
	/// sends as a single chunk if the body is Data and the chunk
	/// chunking is ignored on non-apple platforms
	public mutating func sign(for account:AWSAccount, signPayload:Bool = false, chunkSize:Int? = nil) {
		let now:Date = Date()
		sign(for: account, now: now, signPayload:signPayload, chunkSize:chunkSize)
	}
	
	///primarily for testing
	mutating func sign(for account:AWSAccount, now:Date, signPayload:Bool = false, chunkSize:Int? = nil) {
#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
		if let chunkSize = chunkSize {
			if let dataBody = httpBody {
				httpBodyStream = InputStream(data: dataBody)
				httpBody = nil
			}
			signChunkingRequest(for: account, date: now, chunkSize: chunkSize)
			return
		} else if httpBodyStream != nil {
			signChunkingRequest(for: account, date: now, chunkSize:URLRequest.minimumAWSChunkSize)	//default chunk size
			return
		}
#endif
		//regular data signing
		let nowComponents:DateComponents = AWSAccount.dateComponents(for:now)
		//add some headers
		addPreAuthHeaders(date:now, signPayload:signPayload)
		//auth header
		let header = newAuthorizationHeader(account: account, now: now, nowComponents: nowComponents, signPayload:signPayload)
		setValue(header, forHTTPHeaderField: "Authorization")
	}
	
	
	///create headers which should be added before auth signing happens
	mutating func addPreAuthHeaders(date:Date, signPayload:Bool = false) {
		let nowComponents:DateComponents = AWSAccount.dateComponents(for:date)
		//credential
		//setValue(AWSAccount.credentialString(now:nowComponents), forHTTPHeaderField: "x-amz-credential")
		setValue(nowComponents.formattedHTTPBasicDate, forHTTPHeaderField: "x-amz-date")
		if let _ = httpBody {
			if signPayload {
				//TODO: verify me
				setValue(sha256HashedBody.hexBytes(uppercase: true), forHTTPHeaderField: "x-amz-content-sha256")
			} else {
				setValue("UNSIGNED-PAYLOAD", forHTTPHeaderField: "x-amz-content-sha256")
			}
		} else {
			//the hash of an empty string
			setValue("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", forHTTPHeaderField: "x-amz-content-sha256")
		}
	}
	
	
	///returns sorted key-value tuples
	func canonicalHeaders()->[(String, String)] {
		return (allHTTPHeaderFields ?? [:])
			.map({ (key, value) -> (String, String)  in
				(key.lowercased(), value)
			})
			.canonicalHeaders(host:url?.host ?? "")
	}
	
	
	func canonicalRequestBeforePayload()->(request:String, signedHeaders:String)? {
		let verb:String = httpMethod ?? "GET"
		guard let encodedURI:String = url?.canonicalPath else { return nil } 	//TODO: "URI Encode"
		let queryString:String = url?.canonicalQuery ?? ""
		let headerValues:[(String, String)] = canonicalHeaders()
		var headers:String = headerValues.map { (key, value) -> String in
			return key + ":" + value
			}.joined(separator: "\n")
		headers.append("\n")
		let signedHeaders:String = headerValues.map({$0.0}).joined(separator: ";")
		
		return ([verb, encodedURI, queryString, headers, signedHeaders].joined(separator: "\n"), signedHeaders)
	}
	
	
	func canonicalRequest(signPayload:Bool)->(request:String, signedHeaders:String)? {
		guard let (beforePayload, signedHeaders) = canonicalRequestBeforePayload() else { return nil }
		let hashedBody:String = signPayload ? sha256HashedBody.hexBytes(uppercase: true)
			/*?? "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"*/ : "UNSIGNED-PAYLOAD"
		return (beforePayload + "\n" + hashedBody, signedHeaders)
	}
	
	
	var sha256HashedBody:Data {
		let bodyData = httpBody ?? Data()
		var sha = SHA256()
		sha.update(data: bodyData)
		return Data(sha.finalize())
	}
	
	
	func stringToSign(account:AWSAccount, now:Date, nowComponents:DateComponents, signPayload:Bool)->(string:String, signedHeaders:String)? {
		let timeString:String = nowComponents.formattedHTTPBasicDate
		guard let (request, signedHeaders) = canonicalRequest(signPayload:signPayload) else { return nil }
		//print("canonical request = \(request)")
		var sha = SHA256()
		sha.update(data: Data(request.utf8))
		let hexHash:String = Data(sha.finalize()).hexBytes()
		
		return ("AWS4-HMAC-SHA256\n" + timeString + "\n" + account.scope(now: nowComponents) + "\n" + hexHash, signedHeaders)
	}
	
	
	func newAuthorizationHeader(account:AWSAccount, now:Date, nowComponents:DateComponents, signPayload:Bool = false)->String? {
		let signingKey = account.keyForSigning(now:nowComponents)
		guard let (string, signedHeaders) = stringToSign(account:account, now:now, nowComponents:nowComponents, signPayload:signPayload)
			else { return nil }
		//print("string to sign = \(string)")
		var signature = HMAC<SHA256>(key: SymmetricKey(data: Data(signingKey)))
		signature.update(data: Data(string.utf8))
		let signatureHex:String = Data(signature.finalize()).hexBytes()
		
		return "AWS4-HMAC-SHA256 Credential=\(account.credentialString(now:nowComponents)),SignedHeaders=\(signedHeaders),Signature=\(signatureHex)"
	}
	
}


#endif
