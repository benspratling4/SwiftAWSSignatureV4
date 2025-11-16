//
//  URLComponents+canonical.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/14/25.
//

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif





extension URLComponents {
	
	var canonicalPath:String {
		//figure out if we need this:
//		if hasDirectoryPath == true {
//			uriString.append("/")
//		}
		
		path.aws_uriEncoded(encodeSlash: false)
	}
	
	var canonicalQuery:String {
		(queryItems ?? [])
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
	
	func canonicalRequestBeforePayload(method:String, headers:[(String, String)])throws ->String {
		var headerString:String = headers.map { (key, value) -> String in
			return key + ":" + value
			}.joined(separator: "\n")
		headerString.append("\n")
		let signedHeaders:String = headers
			.map(\.0)
			.joined(separator: ";")
		return [method, canonicalPath, canonicalQuery, headerString, signedHeaders]
			.joined(separator: "\n")
	}
	
}
