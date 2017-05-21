//
//  Chunking.swift
//  SwiftAWSSignatureV4
//
//  Created by Ben Spratling on 5/19/17.
//
//

import Foundation
import Cryptor

extension UInt64 {
	
	fileprivate static let hexStrings:[String] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
	
	///
	var bytesAsHex:String {
		
		var bytes:[String] = []
		var tempInt:UInt64 = self
		while tempInt > 0 {
			let lowBits:Int = Int(tempInt % 16)
			bytes.insert(UInt64.hexStrings[lowBits], at:0)
			tempInt = tempInt >> 4
		}
		//for ease of calculating total metadata length, prepend '0's to reach constant length
		while bytes.count < 16 {
			bytes.insert("0", at: 0)
		}
		return bytes.joined()
	}
}


extension URLRequest {
	///amazon's documentation is ambiguous as to whether the minimum chunk size is 8kB or 8kiB
	public static let minimumAWSChunkSize:Int = 8192
	
	///the request must already include a "Content-Length" header, and a .httpBodyStream
	public func signedChunkingRequest(for account:AWSAccount, chunkSize:Int = URLRequest.minimumAWSChunkSize)->URLRequest? {
		let now:Date = Date()
		return signedChunkingRequest(for:account, date:now, chunkSize:chunkSize)
	}
	
	///so date can be set explicitly for testing
	func signedChunkingRequest(for account:AWSAccount, date:Date, chunkSize:Int)->URLRequest? {
		guard let originalStream:InputStream = httpBodyStream
			,let url:URL = url
			,let lengthString:String = value(forHTTPHeaderField: "Content-Length")
			,let totalLength = UInt64(lengthString)
			,chunkSize >= URLRequest.minimumAWSChunkSize
			else {
				return nil
		}
		
		var newRequest = URLRequest(url: url)
		newRequest.httpMethod = httpMethod
		newRequest.addChunkingPreAuthHeaders(date: date)
		//add all headers, except content-length
		var includedContentEncoding:Bool = false
		if let originalHeaders:[String:String] = allHTTPHeaderFields {
			for (key, value) in originalHeaders {
				if key == "Content-Length" { continue }
				if key == "Content-Encoding" {
					newRequest.addValue("aws-chunked," + value, forHTTPHeaderField: key)
					includedContentEncoding = true
					continue }
				newRequest.addValue(value, forHTTPHeaderField: key)
			}
		}
		if !includedContentEncoding {
			newRequest.addValue("aws-chunked", forHTTPHeaderField: "Content-Encoding")
		}
		//newRequest.addValue("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", forHTTPHeaderField: "x-amz-content-sha256")
		newRequest.addValue("\(totalLength)", forHTTPHeaderField: "x-amz-decoded-content-length")
		//calculate new length
		let numberOfNonZeroChunks:UInt64 = (totalLength / UInt64(chunkSize))
		//always use
		let lengthOfZeroChunk:Int = ChunkedStream.chunkSignatureIntro.count + 64 + 4 /*\r\n\r\n*/ + 16 /*.bytesAsHex*/
		let lengthOfNonZeroChunk:Int = lengthOfZeroChunk + chunkSize
		var extraChunkLength:UInt64 = totalLength % UInt64(chunkSize)
		if extraChunkLength > 0 {
			extraChunkLength += UInt64(lengthOfZeroChunk)
		}
		
		let totalLengthWithMetaData:UInt64 = (numberOfNonZeroChunks * UInt64(lengthOfNonZeroChunk)) + UInt64(lengthOfZeroChunk) + extraChunkLength
		print("said \(totalLengthWithMetaData) total length")
		newRequest.addValue("\(totalLengthWithMetaData)", forHTTPHeaderField: "Content-Length")
		let nowComponents:DateComponents = AWSAccount.dateComponents(for:date)
		guard let (authheader, seedSignature) = newRequest.newChunkingAuthorizationHeader(account: account, now: date, nowComponents: nowComponents) else { return nil }
		newRequest.setValue(authheader, forHTTPHeaderField: "Authorization")
		let timeString:String = HTTPDate(now: nowComponents)
		
		let timeAndScopeString:String = timeString + "\n" + account.scope(now: nowComponents)
		guard let signingKey:[UInt8] = account.keyForSigning(now: nowComponents) else {
			return nil
		}
		/*let newStream:InputStream = ChunkedStream(account: account, originalStream: originalStream, originalContentLength: totalLength, chunkSize: chunkSize, timeAndScope:timeAndScopeString, signingKey:signingKey, seedSignature: seedSignature)*/
		let newStream:InputStream = ChunkedBodyStreamComponents(account: account, originalStream: originalStream, originalContentLength: totalLength, chunkSize: chunkSize, timeAndScope:timeAndScopeString, signingKey:signingKey, seedSignature: seedSignature).stream
		newRequest.httpBodyStream = newStream
		return newRequest
	}
	
	mutating func addChunkingPreAuthHeaders(date:Date) {
		let nowComponents:DateComponents = AWSAccount.dateComponents(for:date)
		setValue(HTTPDate(now:nowComponents), forHTTPHeaderField: "Date")
		setValue("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", forHTTPHeaderField: "x-amz-content-sha256")
	}
	
	func chunkingStringToSign(account:AWSAccount, now:Date, nowComponents:DateComponents)->(string:String, signedHeaders:String)? {
		let timeString:String = HTTPDate(now: nowComponents)
		guard let (beforePayload, signedHeaders) = canonicalRequestBeforePayload() else {
			return nil
		}
		let canonicalRequestString:String = beforePayload + "\n" + "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
		
		print("canonical request = \(canonicalRequestString)")
		let hashOfCanonicalRequest:[UInt8] = Digest(using: .sha256).update(string: canonicalRequestString)?.final() ?? []
		let hexHash:String = CryptoUtils.hexString(from: hashOfCanonicalRequest)
		
		return ("AWS4-HMAC-SHA256\n" + timeString + "\n" + account.scope(now: nowComponents) + "\n" + hexHash, signedHeaders)
	}
	
	
	func seedSignature(account:AWSAccount, now:Date, nowComponents:DateComponents)->(signature:String, headers:String)? {
		guard let signingKey:[UInt8] = account.keyForSigning(now:nowComponents)
			,let (string, signedHeaders) = chunkingStringToSign(account:account, now:now, nowComponents:nowComponents)
			else {
				return nil
		}
		print("string to sign = \(string)")
		let signature:[UInt8] = HMAC(using:HMAC.Algorithm.sha256, key: Data(signingKey)).update(byteArray: CryptoUtils.byteArray(from:string))!.final()
		let signatureHex:String = CryptoUtils.hexString(from: signature)
		return (signatureHex, signedHeaders)
	}
	
	func newChunkingAuthorizationHeader(account:AWSAccount, now:Date, nowComponents:DateComponents)->(headerValue:String, seedSignature:String)? {
		guard let (signature, signedHeaders) = seedSignature(account: account, now: now, nowComponents: nowComponents) else {
			return nil
		}
		return ("AWS4-HMAC-SHA256 Credential=\(account.credentialString(now:nowComponents)),SignedHeaders=\(signedHeaders),Signature=\(signature)", signature)
	}
	
	
}


public class ChunkedBodyStreamComponents {
	
	
	static let chunkSignatureIntro:Data = ";chunk-signature=".data(using: .utf8)!
	
	static let chunkSignatureNewLine:Data = "\r\n".data(using: .utf8)!
	
	private let timeAndScope:String
	
	private var previousSignature:String
	
	private let signingKey:[UInt8]
	
	public init(account:AWSAccount, originalStream:InputStream, originalContentLength:UInt64, chunkSize:Int, timeAndScope:String, signingKey:[UInt8], seedSignature:String) {
		self.account = account
		self.originalInputStream = originalStream
		self.originalContentLength = originalContentLength
		self.chunkSize = chunkSize
		self.previousSignature = seedSignature
		self.timeAndScope = timeAndScope
		self.signingKey = signingKey
		//precompute all data?
		originalStream.open()
	}
	
	public var stream:InputStream {
		return InputStream(data: cheat())
	}
	
	
	private var bytesToSend:Data = Data()
	private var sentBodyBytes:Int = 0
	private var chunkSize:Int
	private let originalContentLength:UInt64
	private let originalInputStream:InputStream
	private let account:AWSAccount
	
	//TODO: write me
	
	
	func stringToSign(thisChunkData:Data)->String {
		var stringComponents:[String] = ["AWS4-HMAC-SHA256-PAYLOAD"]
		stringComponents.append(timeAndScope)
		stringComponents.append(previousSignature)
		stringComponents.append("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")	//hash("")
		guard let thisHash:String = (Digest(using: .sha256).update(data: thisChunkData)?.final()).map({ CryptoUtils.hexString(from: $0).uppercased() }) else { return "" }
		stringComponents.append(thisHash.lowercased())
		return stringComponents.joined(separator: "\n")
	}
	
	func chunkSignature(_ data:Data)->String {
		let string = stringToSign(thisChunkData: data)
		print("string to sign = \(string)")
		let signature:[UInt8] = HMAC(using:HMAC.Algorithm.sha256, key: Data(signingKey)).update(byteArray: CryptoUtils.byteArray(from:string))!.final()
		return CryptoUtils.hexString(from: signature)
	}
	
	func chunkBody(content:Data)->Data? {
		guard let length:Data = UInt64(content.count).bytesAsHex.data(using: .utf8) else { return nil }
		let signature:String = chunkSignature(content).lowercased()
		guard let sig:Data = signature.data(using: .utf8) else { return nil }
		
		previousSignature = signature
		return length + ChunkedStream.chunkSignatureIntro + sig + ChunkedStream.chunkSignatureNewLine + content + ChunkedStream.chunkSignatureNewLine
	}
	
	///for testing before implementing streaming
	/// reads all data from original stream, write it into
	func cheat()->Data {
		let allData:Data = originalInputStream.allData
		
		let numberOfFullSizeChunks:Int = allData.count / chunkSize
		
		var chunks:[Data] = []
		for i in 0..<numberOfFullSizeChunks {
			let subData:Data = allData.subdata(in: (i*chunkSize)..<((i+1)*chunkSize))
			print("chunk size = \(subData.count)")
			chunks.append(subData)
		}
		if allData.count % chunkSize != 0 {
			let overFlowData = allData.subdata(in: (numberOfFullSizeChunks*chunkSize)..<allData.count)
			print("chunk size = \(overFlowData.count)")
			chunks.append(overFlowData)
		}
		chunks.append(Data())
		
		var finalBody:Data = Data()
		
		for chunk in chunks {
			guard let chunkData:Data = chunkBody(content: chunk)
				else {
					continue
			}
			print("chunk length = \(chunkData.count)")
			finalBody.append(chunkData)
		}
		print("finalbody count = \(finalBody.count)")
		return finalBody
	}
	
}



public class ChunkedStream : InputStream {
	
	static let chunkSignatureIntro:Data = ";chunk-signature=".data(using: .utf8)!
	
	static let chunkSignatureNewLine:Data = "\r\n".data(using: .utf8)!
	
	private let timeAndScope:String
	
	private var previousSignature:String
	
	private let signingKey:[UInt8]
	
	public init(account:AWSAccount, originalStream:InputStream, originalContentLength:UInt64, chunkSize:Int, timeAndScope:String, signingKey:[UInt8], seedSignature:String) {
		self.account = account
		self.originalInputStream = originalStream
		self.originalContentLength = originalContentLength
		self.chunkSize = chunkSize
		self.previousSignature = seedSignature
		self.timeAndScope = timeAndScope
		self.signingKey = signingKey
		//precompute all data?
		
		
		super.init(data: Data())
	}
	
	private var bytesToSend:Data = Data()
	private var sentBodyBytes:Int = 0
	private var chunkSize:Int
	private let originalContentLength:UInt64
	private let originalInputStream:InputStream
	private let account:AWSAccount
	
	//TODO: write me
	
	
	func stringToSign(thisChunkData:Data)->String {
		var stringComponents:[String] = ["AWS4-HMAC-SHA256-PAYLOAD"]
		stringComponents.append(timeAndScope)
		stringComponents.append(previousSignature)
		stringComponents.append("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")	//hash("")
		guard let thisHash:String = (Digest(using: .sha256).update(data: thisChunkData)?.final()).map({ CryptoUtils.hexString(from: $0).uppercased() }) else { return "" }
		previousSignature = thisHash
		stringComponents.append(thisHash)
		return stringComponents.joined(separator: "\n")
	}
	
	func chunkSignature(_ data:Data)->String {
		let string = stringToSign(thisChunkData: data)
		let signature:[UInt8] = HMAC(using:HMAC.Algorithm.sha256, key: Data(signingKey)).update(byteArray: CryptoUtils.byteArray(from:string))!.final()
		return CryptoUtils.hexString(from: signature)
	}
	
	func chunkBody(content:Data)->Data? {
		guard let length:Data = UInt64(content.count).bytesAsHex.data(using: .utf8)
			,let sig:Data = chunkSignature(content).data(using: .utf8)
			else { return nil }
		
		return length + ChunkedStream.chunkSignatureIntro + sig + ChunkedStream.chunkSignatureNewLine + content + ChunkedStream.chunkSignatureNewLine
	}
	
	///for testing before implementing streaming
	/// reads all data from original stream, write it into
	func cheat() {
		let allData:Data = originalInputStream.allData
		
		let numberOfFullSizeChunks:Int = allData.count / chunkSize
		
		var chunks:[Data] = []
		for i in 0..<numberOfFullSizeChunks {
			let subData:Data = allData.subdata(in: (i*chunkSize)..<((i+1)*chunkSize))
			chunks.append(subData)
		}
		if allData.count % chunkSize != 0 {
			let overFlowData = allData.subdata(in: (numberOfFullSizeChunks*chunkSize)..<allData.count)
			chunks.append(overFlowData)
		}
		chunks.append(Data())
		
		var finalBody:Data = Data()
		
		for chunk in chunks {
			guard let chunkData:Data = chunkBody(content: chunk)
				else {
				continue
			}
			finalBody.append(chunkData)
		}
		
		
	}
	
}


extension InputStream {
	
	var allData:Data {
		var data:Data = Data()
		let bufferLength:Int = 1000
		var buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
		while hasBytesAvailable {
			let readByteCount:Int = read(buffer, maxLength: bufferLength)
			data.append(buffer, count: readByteCount)
		}
		buffer.deallocate(capacity: bufferLength)
		return data
	}
	
}
