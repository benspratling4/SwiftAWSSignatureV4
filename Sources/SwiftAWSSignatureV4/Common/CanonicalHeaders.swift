//
//  CanonicalHeaders.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/14/25.
//

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif



extension Array where Element == (String, String) {
	
	///returns an array of tulpes of the canonical header names conditioned and sorted in proper order.
	func canonicalHeaders(host:String)->[(name:String, value:String)] {
		var headers = map {
				($0.0, $0.1.trimmingCharacters(in: .whitespaces))
			}
			.filter { (name, _) in
				return name == "host"
					|| name == "content-type"
//					|| name == "range"	//may need to re-add for some tests
//					|| name == "date"	//may need to re-add for some tests
					|| name.hasPrefix("x-amz-")
			}
		if !headers.contains(where: { $0.0 == "host" }) {
			headers.append(("host", host))
		}
		return headers.sorted(by:{ $0.0 < $1.0 })
	}
	
}
