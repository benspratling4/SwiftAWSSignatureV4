//
//  HTTPAuthHeaderTests.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/15/25.
//


#if HTTPTypes

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif

import Testing
@testable import SwiftAWSSignatureV4
import Crypto
import HTTPTypes

@Suite
struct HTTPAuthHeaderTests {
	
	//for this test to work, you need to modify the canonical headers to use the range header
	/*
	@Test
	func testExampleGet() async throws {
		let url = try #require(URL(string:"https://examplebucket.s3.amazonaws.com/test.txt"))
		var request = HTTPRequest(method:.get, url: url)
		request.headerFields[.range] = "bytes=0-9"
		let account = AWSAccount(serviceName: "s3", region: "us-east-1", accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		// (Fri, 24 May 2013 00:00:00 GMT)
		let date = DateComponents(year: 2013, month: 5, day: 24, hour: 0, minute: 0, second: 0, weekday: 6)
		
		var hash = SHA256()
		hash.update(data: Data())
		let hashOut = Data(hash.finalize())
		
		let signature = try request.awsSigV4Signed(account, bodySha256Hash: hashOut, date: date)
		try #require(signature.headerFields[.authorization
							  ] == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
	}
	 */
	
	
	
	//for this test to work, you need to modify the canonical headers to use the date header
	/*
	@Test
	func testExamplePut()async throws {
		let url = try #require(URL(string:"https://examplebucket.s3.amazonaws.com/test$file.text"))
		var request = HTTPRequest(method:.put, url: url)
		request.headerFields[HTTPField.Name("x-amz-storage-class")!] = "REDUCED_REDUNDANCY"
		request.headerFields[.date] = "Fri, 24 May 2013 00:00:00 GMT"
		let account = AWSAccount(serviceName: "s3", region: "us-east-1", accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		// (Fri, 24 May 2013 00:00:00 GMT)
		let date = DateComponents(year: 2013, month: 5, day: 24, hour: 0, minute: 0, second: 0, weekday: 6)
		
		var hash = SHA256()
		hash.update(data: Data("Welcome to Amazon S3.".utf8))
		let hashOut = Data(hash.finalize())
		
		let signature = try request.awsSigV4Signed(account, bodySha256Hash: hashOut, date: date)
		try #require(signature.headerFields[.authorization
							  ] == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")
	}
	*/
	
}


#endif
