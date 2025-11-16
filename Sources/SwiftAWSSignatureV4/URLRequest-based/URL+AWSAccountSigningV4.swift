//
//  URL+AWSAccountSigningV4.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/12/25.
//

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif
import Crypto



extension URL {
	
	
	///Generate a presigned URL
	///expires is in seconds
	///Assumes GET, no extra x-amz headers
	public mutating func presignedGET(for account:AWSAccount, expires:Int, date:Date? = nil)throws {
		//https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
		
		let dateComponents = AWSAccount.dateComponents(for:date ?? Date())
		let intermediateUrl = try self.augmentedForSigning(account: account, expires: expires, dateComponents: dateComponents)
		let stringToSign = intermediateUrl.stringToSign(dateComponents: dateComponents, account: account)
		let signingKey = account.keyForSigning(now:dateComponents)
		var signature = HMAC<SHA256>(key: SymmetricKey(data: Data(signingKey)))
		signature.update(data: Data(stringToSign.utf8))
		let signatureHex:String = Data(signature.finalize()).hexBytes()
		guard let final = URL(string: intermediateUrl.absoluteString + "&X-Amz-Signature=" + signatureHex) else {
			//in practive this doesn't happen
			throw URLSigningError.failedToCreateFinalSignature
		}
		self = final
	}
	
	
	internal func augmentedForSigning(account:AWSAccount, expires:Int, dateComponents:DateComponents)throws->URL {
		guard var components:URLComponents = URLComponents(url: self, resolvingAgainstBaseURL: false) else {
			throw URLSigningError.failedToResolveUrlComponents
		}
		
		//prepend lots of query parameters we can set before signing
		var queryItems = components.queryItems ?? []
		queryItems.append(URLQueryItem(name: "X-Amz-Algorithm", value: "AWS4-HMAC-SHA256"))
		
		let credentialString:String = account.credentialString(now:dateComponents)//.aws_uriEncoded(encodeSlash: true)
		
		queryItems.append(URLQueryItem(name: "X-Amz-Credential", value: credentialString))
		queryItems.append(URLQueryItem(name: "X-Amz-Date", value: dateComponents.formattedHTTPBasicDate))
		queryItems.append(URLQueryItem(name: "X-Amz-Expires", value: "\(expires)"))
		//TODO: support for other headers?
		queryItems.append(URLQueryItem(name: "X-Amz-SignedHeaders", value: "host"))
		components.queryItems = queryItems
		
		//now get the url with all new parameters except the signature
		components.percentEncodedQuery = components.percentEncodedQuery?.replacingOccurrences(of: "/", with: "%2F")
		guard let intermediateUrl = components.url else {
			throw URLSigningError.failedToCreateIntermediateUrl
		}
		
		return intermediateUrl
	}
	
	
	internal func stringToSign(dateComponents:DateComponents, account:AWSAccount)->String {
		let timeString:String = dateComponents.formattedHTTPBasicDate
		var sha = SHA256()
		sha.update(data: Data(canonicalRequestWithoutBodyOrHeaders.utf8))
		let hexHash:String = Data(sha.finalize()).hexBytes()
		return "AWS4-HMAC-SHA256\n" + timeString + "\n" + account.scope(now: dateComponents) + "\n" + hexHash
	}
	
	
	internal var canonicalPath:String {
		var uriString:String = path
		if hasDirectoryPath == true {
			uriString.append("/")
		}
		let encodedURI:String = uriString.aws_uriEncoded(encodeSlash: false)
		return encodedURI
	}
	
	
	internal var canonicalQuery:String {
		var queryString:String? = query
		if let components = URLComponents(url: self, resolvingAgainstBaseURL: false)
			,let queryItems = components.queryItems {
			queryString = queryItems
				.map({ (name:$0.name.aws_uriEncoded(encodeSlash: true)
						, value:($0.value ?? "").aws_uriEncoded(encodeSlash: true) )
				})
				.sorted(by: {
					if $0.name < $1.name {
						return true
					}
					if $0.name > $1.name {
						return false
					}
					return $0.value < $1.value
				})
				.map({ $0.name + "=" + $0.value })
				.joined(separator:"&")
		}
		
		return queryString ?? ""
	}
	
	
	internal var canonicalRequestWithoutBodyOrHeaders:String {
		let components = URLComponents(url: self, resolvingAgainstBaseURL: false)!	//fix me
		return "GET\n" + components.canonicalPath + "\n" + components.canonicalQuery + "\nhost:" + (components.host ?? "") + "\n\nhost\nUNSIGNED-PAYLOAD"
	}
	
	
}


public enum URLSigningError : Error {
	case failedToResolveUrlComponents
	case failedToCreateIntermediateUrl
	case failedToCreateFinalSignature
}
