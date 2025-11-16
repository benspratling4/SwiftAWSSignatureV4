//
//  HTTPRequest+CanonicalHeaders.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/14/25.
//


#if HTTPTypes

//#if canImport(HTTPTypes)

import HTTPTypes

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif




extension HTTPRequest {
	
	var canonicalHeaders:[(name:String, value:String)] {
		headerFields
			.map({ field in
				(field.name.canonicalName, field.value)
			})
			.canonicalHeaders(host: authority ?? "")
	}
	
	
	func addingPreAuthFields(date:DateComponents, bodyHash:String)throws->HTTPRequest {
		var newRequest = self
		guard let amzDateName = HTTPField.Name("x-amz-date")
			,let contentShaHashFieldName = HTTPField.Name("x-amz-content-sha256")
			else {
			throw URLError(.badURL)
		}
		newRequest.headerFields[amzDateName] = date.formattedHTTPBasicDate
		newRequest.headerFields[contentShaHashFieldName] = bodyHash
		
		return newRequest
	}
	
}


//#endif

#endif

