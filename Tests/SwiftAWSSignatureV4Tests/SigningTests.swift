//
//  SigningTests.swift
//  SwiftAWSSignatureV4Tests
//
//  Created by Christopher G Prince on 2/3/19.
//

@testable import SwiftAWSSignatureV4
import XCTest
import Cryptor

// These tests are based off of https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html#signature-v4-test-suite-derived-creds
// So far, not doing anything with payload signing-- assuming it is empty.

class SigningTests : XCTestCase {
    // Example:
//        GET /?Param2=value2&Param1=value1 HTTP/1.1
//        Host:example.amazonaws.com
//        X-Amz-Date:20150830T123600Z
    static let date = "20150830T123600Z"
    static let baseURL = "example.amazonaws.com"
    static let urlQueryParams = ["Param2": "value2", "Param1": "value1"]
    static let urlString = "https://\(baseURL)/?Param2=value2&Param1=value1"
    static let url = URL(string: urlString)!
    
    // Should put trailing "/" if no args.
    static let urlNoParams = URL(string: "https://\(baseURL)/")!
    
    static let service = "service" // more realistically, this would be "sns"
    static let region = "us-east-1"
    static let secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    static let accessKeyId = "AKIDEXAMPLE"

    func canonicalRequestWithSignedPayload(paramsInURL: Bool) {
        var request:URLRequest!
        if paramsInURL {
            request = URLRequest(url: SigningTests.url)
        }
        else {
            request = URLRequest(url: SigningTests.urlNoParams)
        }
        
        request.setValue(SigningTests.baseURL, forHTTPHeaderField: "Host")
        request.setValue(SigningTests.date, forHTTPHeaderField: "X-Amz-Date")
        request.httpMethod = "GET"
        
        var queryParams: [String: String]?
        if !paramsInURL {
            queryParams = SigningTests.urlQueryParams
        }
        
        let result = request.canonicalRequest(signPayload: true, urlQueryParams: queryParams)
        print("result:\n\(result!.request)")
        
        let expected = """
            GET
            /
            Param1=value1&Param2=value2
            host:example.amazonaws.com
            x-amz-date:20150830T123600Z
            
            host;x-amz-date
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            """
        print("expected:\n\(expected)")
        XCTAssert(result!.request == expected)
    }

    func testCanonicalRequestWithSignedPayloadParamsInURL() {
        canonicalRequestWithSignedPayload(paramsInURL: true)
    }
    
    func testCanonicalRequestWithSignedPayloadParamsNotInURL() {
        canonicalRequestWithSignedPayload(paramsInURL: false)
    }
    
    func hashCanonicalRequestWithSignedPayload(paramsInURL: Bool) {
        var request:URLRequest!
        if paramsInURL {
            request = URLRequest(url: SigningTests.url)
        }
        else {
            request = URLRequest(url: SigningTests.urlNoParams)
        }
        
        request.setValue(SigningTests.baseURL, forHTTPHeaderField: "Host")
        request.setValue(SigningTests.date, forHTTPHeaderField: "X-Amz-Date")
        request.httpMethod = "GET"
        
        var queryParams: [String: String]?
        if !paramsInURL {
            queryParams = SigningTests.urlQueryParams
        }
        
        guard let (hashedRequest, _) = request.hashCanonicalRequest(signPayload: true, urlQueryParams: queryParams) else {
            XCTFail()
            return
        }
        
        print("hashedRequest: \(hashedRequest)")
        let expected = "816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0"
        XCTAssert(hashedRequest == expected)
    }
    
    func testHashCanonicalRequestWithSignedPayloadParamsInURL() {
        hashCanonicalRequestWithSignedPayload(paramsInURL: true)
    }
    
    func testHashCanonicalRequestWithSignedPayloadParamsNotInURL() {
        hashCanonicalRequestWithSignedPayload(paramsInURL: false)
    }
    
    func stringToSignWithSignedPayload(paramsInURL: Bool) {
        var request:URLRequest!
        if paramsInURL {
            request = URLRequest(url: SigningTests.url)
        }
        else {
            request = URLRequest(url: SigningTests.urlNoParams)
        }
        
        request.setValue(SigningTests.baseURL, forHTTPHeaderField: "Host")
        request.setValue(SigningTests.date, forHTTPHeaderField: "X-Amz-Date")
        request.httpMethod = "GET"
        
        let formatter = DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        let date = formatter.date(from: SigningTests.date)!
        let dateComponents = AWSAccount.dateComponents(for: date)
        
        let account = AWSAccount(serviceName: SigningTests.service, region: SigningTests.region, accessKeyID: SigningTests.accessKeyId, secretAccessKey: SigningTests.secretKey)

        var queryParams: [String: String]?
        if !paramsInURL {
            queryParams = SigningTests.urlQueryParams
        }
        
        guard let (stringToSign,_) = request.stringToSign(account: account, urlQueryParams: queryParams, now: date, nowComponents: dateComponents, signPayload: true) else {
            XCTFail()
            return
        }
        
        let expected = """
            AWS4-HMAC-SHA256
            20150830T123600Z
            20150830/us-east-1/service/aws4_request
            816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0
            """
        
        print("stringToSign:\n\(stringToSign)")
        XCTAssert(stringToSign == expected)
    }
    
    func testStringToSignWithSignedPayloadParamsInURL() {
        stringToSignWithSignedPayload(paramsInURL: true)
    }

    func testStringToSignWithSignedPayloadParamsNotInURL() {
        stringToSignWithSignedPayload(paramsInURL: false)
    }
    
    // See https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    func testCalculateSigningKey() {
        /*
            Example inputs:
                HMAC(HMAC(HMAC(HMAC("AWS4" + kSecret,"20150830"),"us-east-1"),"iam"),"aws4_request")
        */
        let account = AWSAccount(serviceName: "iam", region: SigningTests.region, accessKeyID: SigningTests.accessKeyId, secretAccessKey: SigningTests.secretKey)
        let formatter = DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        let date = formatter.date(from: SigningTests.date)!
        let dateComponents = AWSAccount.dateComponents(for: date)
        
        guard let signingKey = account.keyForSigning(now:dateComponents) else {
            XCTFail()
            return
        }
        
        let hexSigningKey = CryptoUtils.hexString(from: signingKey)
        print("hexSigningKey: \(hexSigningKey)")
        
        let expected = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        XCTAssert(hexSigningKey == expected)
    }
    
    func testCalculateSignature() {
        let account = AWSAccount(serviceName: "iam", region: SigningTests.region, accessKeyID: SigningTests.accessKeyId, secretAccessKey: SigningTests.secretKey)
        let formatter = DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        let date = formatter.date(from: SigningTests.date)!
        let dateComponents = AWSAccount.dateComponents(for: date)
        
        guard let signingKey = account.keyForSigning(now:dateComponents) else {
            XCTFail()
            return
        }
        
        // Example string to sign from: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
        
        let exampleStringToSign = """
            AWS4-HMAC-SHA256
            20150830T123600Z
            20150830/us-east-1/iam/aws4_request
            f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59
            """
        
        let signatureHex = URLRequest.computeSignature(signingKey: signingKey, stringToSign: exampleStringToSign)
        
        print("signatureHex: \(signatureHex)")
        let expected = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        XCTAssert(expected == signatureHex)
    }
    
    func newAuthorizationHeaderWithSignedPayload(paramsInURL: Bool) {
        var request:URLRequest!
        if paramsInURL {
            request = URLRequest(url: SigningTests.url)
        }
        else {
            request = URLRequest(url: SigningTests.urlNoParams)
        }
        
        request.setValue(SigningTests.baseURL, forHTTPHeaderField: "Host")
        request.setValue(SigningTests.date, forHTTPHeaderField: "X-Amz-Date")
        request.httpMethod = "GET"
        
        let formatter = DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        let date = formatter.date(from: SigningTests.date)!
        let dateComponents = AWSAccount.dateComponents(for: date)
        
        let account = AWSAccount(serviceName: SigningTests.service, region: SigningTests.region, accessKeyID: SigningTests.accessKeyId, secretAccessKey: SigningTests.secretKey)
        
        var queryParams: [String: String]?
        if !paramsInURL {
            queryParams = SigningTests.urlQueryParams
        }
        
        guard let authHeader = request.newAuthorizationHeader(account: account, urlQueryParams: queryParams, now: date, nowComponents: dateComponents, signPayload: true) else {
            XCTFail()
            return
        }
        
        print("authHeader: \(authHeader)")
        
        let expected = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        XCTAssert(expected == authHeader)
    }
    
    func testNewAuthorizationHeaderWithSignedPayloadParamsInURL() {
        newAuthorizationHeaderWithSignedPayload(paramsInURL: true)
    }
    
    func testNewAuthorizationHeaderWithSignedPayloadParamsNotInURL() {
        newAuthorizationHeaderWithSignedPayload(paramsInURL: false)
    }
    
    // This is an actual use case. i.e., how the signing should appear in an application's code.
    func addSigningInformationToRequestWithPayloadSigning(paramsInURL: Bool) {
        var request:URLRequest!
        if paramsInURL {
            request = URLRequest(url: SigningTests.url)
        }
        else {
            request = URLRequest(url: SigningTests.urlNoParams)
        }

        request.setValue(SigningTests.baseURL, forHTTPHeaderField: "Host")
        
        // The URLRequest sign method adds this header.
        // request.setValue(SigningTests.date, forHTTPHeaderField: "X-Amz-Date")
        
        request.httpMethod = "GET"
        
        // This date usage shouldn't be needed in an actual application. Just have it here to test against sample data.
        let formatter = DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        let date = formatter.date(from: SigningTests.date)!
        
        let account = AWSAccount(serviceName: SigningTests.service, region: SigningTests.region, accessKeyID: SigningTests.accessKeyId, secretAccessKey: SigningTests.secretKey)
        
        var queryParams: [String: String]?
        if !paramsInURL {
            queryParams = SigningTests.urlQueryParams
        }
        
        request.sign(for: account, urlQueryParams: queryParams, signPayload: true, date: date)
        
        /*
        GET /?Param2=value2&Param1=value1 HTTP/1.1
        Host:example.amazonaws.com
        X-Amz-Date:20150830T123600Z
        Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500
        */
        
        guard let headers = request.allHTTPHeaderFields else {
            XCTFail()
            return
        }
        
        XCTAssert(headers["Host"] == "example.amazonaws.com")
        XCTAssert(headers["X-Amz-Date"] == "20150830T123600Z")
        
        guard let auth = headers["Authorization"] else {
            XCTFail()
            return
        }
        
        print("headers['Authorization']: \(auth)")
        
        XCTAssert(headers["Authorization"] == "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500")
    }
    
    func testAddSigningInformationToRequestWithPayloadSigningParamsInURL() {
        addSigningInformationToRequestWithPayloadSigning(paramsInURL: true)
    }
    
    func testAddSigningInformationToRequestWithPayloadSigningParamsNotInURL() {
        addSigningInformationToRequestWithPayloadSigning(paramsInURL: false)
    }
}

