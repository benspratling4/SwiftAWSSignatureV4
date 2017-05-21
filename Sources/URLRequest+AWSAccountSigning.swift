//
//  AmazonS3.swift
//
//  Created by Ben Spratling on 3/30/17.
//
//

import Foundation
import Dispatch
import Cryptor


//Based on http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html


extension UInt8 {
	private static let hexChars:[String] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
	var hex:String {
		let lowBits:UInt8 = self & 0x0F
		let highBits:UInt8 = (self >> 4)
		return UInt8.hexChars[Int(highBits)] + UInt8.hexChars[Int(lowBits)]
	}
}


extension URLRequest {
	
	///adds an Authorization header
	public mutating func sign(for AWSAccount:AWSAccount, signPayload:Bool = false) {
		let now:Date = Date()
		sign(for: AWSAccount, now: now, signPayload:signPayload)
	}
	
	///primarily for testing
	mutating func sign(for AWSAccount:AWSAccount, now:Date, signPayload:Bool = false) {
		let nowComponents:DateComponents = AWSAccount.dateComponents(for:now)
		//add some headers
		addPreAuthHeaders(for:AWSAccount, date:now, signPayload:signPayload)
		//auth header
		let header = newAuthorizationHeader(AWSAccount: AWSAccount, now: now, nowComponents: nowComponents, signPayload:signPayload)
		setValue(header, forHTTPHeaderField: "Authorization")
	}
	
	
	///create headers which should be added before auth signing happens
	mutating func addPreAuthHeaders(for AWSAccount:AWSAccount, date:Date, signPayload:Bool = false) {
		let nowComponents:DateComponents = AWSAccount.dateComponents(for:date)
		//credential
		//setValue(AWSAccount.credentialString(now:nowComponents), forHTTPHeaderField: "x-amz-credential")
		setValue(HTTPDate(now:nowComponents), forHTTPHeaderField: "Date")
		if let _ = httpBody {
			if signPayload {
				//TODO: verify me
				setValue(sha256HashedBody?.map{$0.hex}.joined(), forHTTPHeaderField: "x-amz-content-sha256")
			} else {
				setValue("UNSIGNED-PAYLOAD", forHTTPHeaderField: "x-amz-content-sha256")
			}
		} else {
			//the hash of an empty string
			setValue("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", forHTTPHeaderField: "x-amz-content-sha256")
		}
	}
	
	///creates a
	func HTTPDate(now:DateComponents)->String {
		let dayName:String = AWSAccount.calendar.shortWeekdaySymbols[now.weekday! - 1]
		let monthShort:String = AWSAccount.calendar.shortMonthSymbols[now.month! - 1]
		let year:String = "\(now.year!)"
		let day:String = "\(now.day!)".prepadded("0", length: 2)
		let hour:String = "\(now.hour!)".prepadded("0", length: 2)
		let minute:String = "\(now.minute!)".prepadded("0", length: 2)
		let second:String = "\(now.second!)".prepadded("0", length: 2)
		return dayName + ", " + day + " " + monthShort + " " + year + " " + hour + ":" + minute + ":" + second + " GMT"
	}
	
	///returns sorted key-value tuples
	func canonicalHeaders()->[(String, String)] {
		let allHeaders = allHTTPHeaderFields ?? [:]
		var headerValues:[(String,String)] = allHeaders.map { (key, value) -> (String, String) in
			return (key.lowercased(), value.trimmingCharacters(in: .whitespaces))
		}
		headerValues = headerValues.filter({ (key0, _) -> Bool in
			return key0 == "host"
				|| key0 == "content-type"
				|| key0.hasPrefix("x-amz-")
		})
		if allHeaders["Host"] == nil, let host:String = url?.host {
			headerValues.append(("host",host))
		}
		headerValues.sort { $0.0 < $1.0 }
		return headerValues
		
	}
	
	
	func canonicalRequest(now:Date, signPayload:Bool)->(request:String, signedHeaders:String)? {
		let verb:String = httpMethod ?? "GET"
		guard var uriString:String = url?.path else { return nil } 	//TODO: "URI Encode"
		var queryString:String? = url?.query
		if queryString != nil {
			uriString.append("?")
		}
		guard let encodedURI:String = uriString.aws_uriEncoded(encodeSlash: false) else { return nil }
		if let queryLongString = queryString {
			let queryItems:[String] = queryLongString.components(separatedBy: "&")
			let reconstituted:[String] = queryItems.map{
				$0.components(separatedBy: "=")
					.flatMap{$0.aws_uriEncoded(encodeSlash: true)}
				.joined(separator: "=")}
			queryString = reconstituted.joined(separator: "&")
		}
		
		let headerValues:[(String, String)] = canonicalHeaders()
		var headers:String = headerValues.map { (key, value) -> String in
			return key + ":" + value
		}.joined(separator: "\n")
		headers.append("\n")
		let signedHeaders:String = headerValues.map({$0.0}).joined(separator: ";")
		
		let hashedBody:String = signPayload ? sha256HashedBody.map { CryptoUtils.hexString(from: $0).uppercased() }
		?? "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" : "UNSIGNED-PAYLOAD"
		
		return ([verb, encodedURI, queryString ?? "", headers, signedHeaders, hashedBody].joined(separator: "\n"), signedHeaders)
	}
	
	
	var sha256HashedBody:[UInt8]? {
		if let bodyData = httpBody {
			return Digest(using: .sha256).update(data: bodyData)?.final()
		} else {
			return Digest(using: .sha256).update(string: "")?.final()
		}
	}
	
	
	func stringToSign(AWSAccount:AWSAccount, now:Date, nowComponents:DateComponents, signPayload:Bool)->(string:String, signedHeaders:String)? {
		let timeString:String = HTTPDate(now: nowComponents)
		guard let (request, signedHeaders) = canonicalRequest(now:now, signPayload:signPayload) else { return nil }
		//print("canonical request = \(request)")
		let hashOfCanonicalRequest:[UInt8] = Digest(using: .sha256).update(string: request)?.final() ?? []
		let hexHash:String = CryptoUtils.hexString(from: hashOfCanonicalRequest)
		
		return ("AWS4-HMAC-SHA256\n" + timeString + "\n" + AWSAccount.scope(now: nowComponents) + "\n" + hexHash, signedHeaders)
	}
	
	
	func newAuthorizationHeader(AWSAccount:AWSAccount, now:Date, nowComponents:DateComponents, signPayload:Bool = false)->String? {
		guard let signingKey:[UInt8] = AWSAccount.keyForSigning(now:nowComponents)
			,let (string, signedHeaders) = stringToSign(AWSAccount:AWSAccount, now:now, nowComponents:nowComponents, signPayload:signPayload)
			else { return nil }
		//print("string to sign = \(string)")
		let signature:[UInt8] = HMAC(using:HMAC.Algorithm.sha256, key: Data(signingKey)).update(byteArray: CryptoUtils.byteArray(from:string))!.final()
		let signatureHex:String = CryptoUtils.hexString(from: signature)
		
		return "AWS4-HMAC-SHA256 Credential=\(AWSAccount.credentialString(now:nowComponents)),SignedHeaders=\(signedHeaders),Signature=\(signatureHex)"
	}
	
}
