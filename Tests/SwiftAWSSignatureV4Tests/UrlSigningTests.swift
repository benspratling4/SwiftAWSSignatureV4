//
//  UrlSigningTests.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 11/13/25.
//
import Testing
@testable import SwiftAWSSignatureV4

#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif





//uses example test values from https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
@Suite
struct UrlSigningTests {
	
	@Test
	func testUrlSigning()throws {
		var url = URL(string:"https://examplebucket.s3.amazonaws.com/test.txt")!
		let account = AWSAccount(serviceName: "s3", region: "us-east-1", accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		var calendar = Calendar(identifier: .iso8601)
		calendar.timeZone = .gmt
		let date = calendar.date(from: DateComponents(year: 2013, month: 05, day: 24, hour: 0, minute: 0, second: 0))!
		try url.presignedGET(for: account, expires: 86400, date: date)
		
//		print(url)
		
		let correctValue = URL(string: "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404")
		
		try #require(url == correctValue)
	}
	
	@Test
	func testCanonicalRequst()throws {
		let url = URL(string:"https://examplebucket.s3.amazonaws.com/test.txt")!
		let account = AWSAccount(serviceName: "s3", region: "us-east-1", accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		var calendar = Calendar(identifier: .iso8601)
		calendar.timeZone = .gmt
		let dateComponents = DateComponents(year: 2013, month: 05, day: 24, hour: 0, minute: 0, second: 0)
		let intermediateUrl = try url.augmentedForSigning(account: account, expires: 86400, dateComponents: dateComponents)
		let canonicalRequest = intermediateUrl.canonicalRequestWithoutBodyOrHeaders
//		print (canonicalRequest)
		let correctValue = """
GET
/test.txt
X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
host:examplebucket.s3.amazonaws.com

host
UNSIGNED-PAYLOAD
"""
		try #require(canonicalRequest == correctValue)
	}
	
	@Test
	func testStringToSign()throws {
		var url = URL(string:"https://examplebucket.s3.amazonaws.com/test.txt")!
		let account = AWSAccount(serviceName: "s3", region: "us-east-1", accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		var calendar = Calendar(identifier: .iso8601)
		calendar.timeZone = .gmt
		let dateComponents = DateComponents(year: 2013, month: 05, day: 24, hour: 0, minute: 0, second: 0)
		let intermediateUrl = try url.augmentedForSigning(account: account, expires: 86400, dateComponents: dateComponents)
		let stringToSign = intermediateUrl.stringToSign(dateComponents: dateComponents, account: account)
//		print(stringToSign)
		
		let correctValue = """
AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04
"""
		try #require(stringToSign == correctValue)
	}
	
}
