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
	mutating func signChunkingRequest(for account:AWSAccount, chunkSize:Int = URLRequest.minimumAWSChunkSize) {
		let now:Date = Date()
		signChunkingRequest(for:account, date:now, chunkSize:chunkSize)
	}
	
	///so date can be set explicitly for testing
	mutating func signChunkingRequest(for account:AWSAccount, date:Date, chunkSize:Int) {
		guard let originalStream:InputStream = httpBodyStream
			,let lengthString:String = value(forHTTPHeaderField: "Content-Length")
			,let totalLength = UInt64(lengthString)
			,chunkSize >= URLRequest.minimumAWSChunkSize
			else {
				return
		}
		
		//var newRequest = URLRequest(url: url)
		//newRequest.httpMethod = httpMethod
		addChunkingPreAuthHeaders(date: date)
		//add all headers, except content-length
		var includedContentEncoding:Bool = false
		if let originalHeaders:[String:String] = allHTTPHeaderFields {
			for (key, value) in originalHeaders {
				if key == "Content-Length" {
					continue }
				if key == "Content-Encoding" {
					setValue("aws-chunked," + value, forHTTPHeaderField: key)
					includedContentEncoding = true
					continue }
				//addValue(value, forHTTPHeaderField: key)
			}
		}
		if !includedContentEncoding {
			addValue("aws-chunked", forHTTPHeaderField: "Content-Encoding")
		}
		addValue("\(totalLength)", forHTTPHeaderField: "x-amz-decoded-content-length")
		//calculate new length
		let numberOfNonZeroChunks:UInt64 = (totalLength / UInt64(chunkSize))
		//always use
		let lengthOfZeroChunk:Int = ChunkedStream.chunkSignatureIntro.count + 64 /*hash output length in hex*/ + 4 /*\r\n\r\n*/ + 16 /*.bytesAsHex*/
		let lengthOfNonZeroChunk:Int = lengthOfZeroChunk + chunkSize
		var extraChunkLength:UInt64 = totalLength % UInt64(chunkSize)
		if extraChunkLength > 0 {
			extraChunkLength += UInt64(lengthOfZeroChunk)
		}
		
		let totalLengthWithMetaData:UInt64 = (numberOfNonZeroChunks * UInt64(lengthOfNonZeroChunk)) + UInt64(lengthOfZeroChunk) + extraChunkLength
		//print("said \(totalLengthWithMetaData) total length")
		setValue("\(totalLengthWithMetaData)", forHTTPHeaderField: "Content-Length")
		let nowComponents:DateComponents = AWSAccount.dateComponents(for:date)
		guard let (authheader, seedSignature) = newChunkingAuthorizationHeader(account: account, now: date, nowComponents: nowComponents) else { return}
		setValue(authheader, forHTTPHeaderField: "Authorization")
		let timeString:String = HTTPDate(now: nowComponents)
		
		let timeAndScopeString:String = timeString + "\n" + account.scope(now: nowComponents)
		guard let signingKey:[UInt8] = account.keyForSigning(now: nowComponents) else {
			return 
		}
		let newStream:InputStream = ChunkedStream(account: account, originalStream: originalStream, originalContentLength: totalLength, chunkSize: chunkSize, finalTotalLength:totalLengthWithMetaData, timeAndScope:timeAndScopeString, signingKey:signingKey, seedSignature: seedSignature)
		httpBodyStream = newStream
		
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
		
		//print("canonical request = \(canonicalRequestString)")
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
		//print("string to sign = \(string)")
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


@objc public class ChunkedStream : InputStream, StreamDelegate {
	
	static let readBufferSize:Int = 8192
	
	static let chunkSignatureIntro:Data = ";chunk-signature=".data(using: .utf8)!
	
	static let chunkSignatureNewLine:Data = "\r\n".data(using: .utf8)!
	
	private let timeAndScope:String
	
	private var previousSignature:String
	
	private let signingKey:[UInt8]
	
	private let delayQueue:DispatchQueue = DispatchQueue(label: "delay chunked stream event queue")
	
	public init(account:AWSAccount, originalStream:InputStream, originalContentLength:UInt64, chunkSize:Int, finalTotalLength:UInt64, timeAndScope:String, signingKey:[UInt8], seedSignature:String) {
		self.account = account
		self.originalInputStream = originalStream
		self.originalContentLength = originalContentLength
		self.chunkSize = chunkSize
		self.previousSignature = seedSignature
		self.timeAndScope = timeAndScope
		self.signingKey = signingKey
		self.finalTotalLength = finalTotalLength
		super.init(data: Data())
	}
	
	private let finalTotalLength:UInt64
	
	
	@objc public override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
		//print("read(_, max:\(len)) (readInCount = \(readInCount))")
		//if possible, read in as many bytes as possible
		while originalInputStream.hasBytesAvailable && bytesToSend.count < len {
			if readInBytes() == 0 {
				break
			}
		}
		
		let readSize:Int = min(len, bytesToSend.count)
		if readSize > 0 {
			bytesToSend.copyBytes(to: buffer, from: 0..<readSize)
			bytesToSend.removeSubrange(0..<readSize)
			sentBodyBytes += readSize
			//print("read \(readSize) bytes")
		}
		
		if UInt64(readInCount) == originalContentLength
			,addMoreChunksIfPossible()
			,let (runloop, mode) = scheduledRunLoopsMode {
			delayQueue.asyncAfter(wallDeadline: .now() + 0.00001, execute: {
				runloop.perform(#selector(ChunkedStream.triggerSendingHasBytesAvailable), target: self, argument: nil, order: 0, modes: [mode])
			})
		}
		if UInt64(readInCount) == originalContentLength && bytesToSend.count == 0 {
			if let (runloop, mode) = scheduledRunLoopsMode {
				delayQueue.asyncAfter(wallDeadline: .now() + 0.00001, execute: {
					runloop.perform(#selector(ChunkedStream.triggerSendingEnd), target: self, argument: nil, order: 1, modes: [mode])
				})
			}
		}
		if bytesToSend.count > 0 {
			if let (runloop, mode) = scheduledRunLoopsMode {
				delayQueue.asyncAfter(wallDeadline: .now() + 0.00001, execute: {
					runloop.perform(#selector(ChunkedStream.triggerSendingHasBytesAvailable), target: self, argument: nil, order: 1, modes: [mode])
				})
			}
		}
		
		return readSize
	}
	
	@objc func triggerSendingHasBytesAvailable(_ sender:AnyObject?) {
		//print("telling delegate there are more bytes available, readbytes = \(readInCount)")
		_delegate?.stream?(self, handle: .hasBytesAvailable)
	}
	
	@objc func triggerSendingEnd(_ sender:AnyObject?) {
		//print("telling delegate we have no more bytes available")
		_delegate?.stream?(self, handle: .endEncountered)
	}
	
	@objc public override func open() {
		//print("open")
		originalInputStream.open()
	}
	
	@objc public override func close() {
		//print("close")
		originalInputStream.close()
	}
	
	
	@objc public override var streamError: Error? {
		return originalInputStream.streamError
	}
	
	@objc public override var streamStatus: Stream.Status {
		let originalStatus:Stream.Status = originalInputStream.streamStatus
		guard case .atEnd = originalStatus else { return originalStatus }
		return UInt64(sentBodyBytes) == finalTotalLength ? .atEnd : .open
	}
	
	public override var hasBytesAvailable: Bool {
		return originalInputStream.hasBytesAvailable || bytesToSend.count > 0
	}
	
	private var buffer:UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: ChunkedStream.readBufferSize)
	
	deinit {
		buffer.deallocate(capacity: ChunkedStream.readBufferSize)
	}
	
	private weak var _delegate:StreamDelegate?
	
	@objc public override var delegate: StreamDelegate? {
		get {
			return _delegate
		}
		set {
			//print("set stream delegate \(newValue)")
			_delegate = newValue ?? self
			if newValue == nil {
				originalInputStream.delegate = nil
			} else {
				originalInputStream.delegate = self
			}
		}
	}
	
	
	var scheduledRunLoopsMode:(RunLoop, RunLoopMode)?
	
	@objc public override func schedule(in aRunLoop: RunLoop, forMode mode: RunLoopMode) {
		scheduledRunLoopsMode = (aRunLoop, mode)
		//print("schedule(in:\(aRunLoop), forMode:\(mode))")
		originalInputStream.schedule(in: aRunLoop, forMode: mode)
	}
	
	@objc public override func remove(from aRunLoop: RunLoop, forMode mode: RunLoopMode) {
		aRunLoop.cancelPerformSelectors(withTarget: self)
		scheduledRunLoopsMode = nil
		//print("remove(from:\(aRunLoop), forMode:\(mode))")
		originalInputStream.remove(from: aRunLoop, forMode: mode)
	}
	
	
	private func readInBytes()->Int {
		let readCount = originalInputStream.read(buffer, maxLength: ChunkedStream.readBufferSize)
		if readCount > 0 {
			collectedBodyBytes.append(buffer, count:readCount)
			readInCount += readCount
			let _ = addMoreChunksIfPossible()
		}
		return readCount
	}
	
	
	public func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
		//print("stream(\(aStream), handle\(eventCode)")
		if aStream === originalInputStream {
			if eventCode == .hasBytesAvailable {
				while originalInputStream.hasBytesAvailable && bytesToSend.count < (2 * chunkSize) {
					let readCount = readInBytes()
					if readCount > 0 {
						//print("read \(readCount) from original stream")
						//processPossibleChunks()
					} else if readCount < 0 {
						//print("stream read error")
						//error
					}
				}
			} else if eventCode == .openCompleted {
				_delegate?.stream?(self, handle: .openCompleted)
			} else if eventCode == .errorOccurred {
				_delegate?.stream?(self, handle: eventCode)
			} else if eventCode == .endEncountered {
				//TODO: write me
				processPossibleChunks()
			}
		}
		
	}
	
	//converts more read bytes into bytes to send, returns true if it did that
	func addMoreChunksIfPossible()->Bool {
		var didWriteMoreBytes:Bool = false
		while (collectedBodyBytes.count > chunkSize
			|| UInt64(readInCount) == originalContentLength)
			&& collectedBodyBytes.count > 0 {
			let readSize:Int = min(chunkSize, collectedBodyBytes.count)
			let subData:Data = collectedBodyBytes.subdata(in: 0..<readSize)
			collectedBodyBytes.removeSubrange(0..<readSize)
			if let body:Data = chunkBody(content:subData) {
				//print("added chunk with \(body.count) bytes")
				bytesToSend.append(body)
				didWriteMoreBytes = true
			}
		}
		if UInt64(readInCount) == originalContentLength && didWriteMoreBytes {
			//end condition - empty
			if let body:Data = chunkBody(content:Data()) {
				bytesToSend.append(body)
				//print("added last chunk")
				
				//endEncountered
			}
		}
		return didWriteMoreBytes
	}
	
	func processPossibleChunks() {
		if addMoreChunksIfPossible() {
			if let (runloop, mode) = scheduledRunLoopsMode {
				delayQueue.asyncAfter(wallDeadline: .now() + 0.00001, execute: {
					runloop.perform(#selector(ChunkedStream.triggerSendingHasBytesAvailable), target: self, argument: nil, order: 0, modes: [mode])
				})
			}
			//delegate?.stream?(self, handle: .hasBytesAvailable)
		}
	}
	
	/// bytes we will send, once sent, they are removed
	private var bytesToSend:Data = Data()
	
	///the running count of how many bytes have been sent
	private var sentBodyBytes:Int = 0
	
	///bytes we've read in from the original stream, once processed, they are removed
	private var collectedBodyBytes:Data = Data()
	
	///total count of btyes
	private var readInCount:Int = 0
	
	private var chunkSize:Int
	
	///how many bytes should be in the original content, without chunking metadata
	private let originalContentLength:UInt64
	private let originalInputStream:InputStream
	private let account:AWSAccount
	
	
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
	
}


extension InputStream {
	
	var allData:Data {
		var data:Data = Data()
		let bufferLength:Int = 1000
		let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
		while hasBytesAvailable {
			let readByteCount:Int = read(buffer, maxLength: bufferLength)
			data.append(buffer, count: readByteCount)
		}
		buffer.deallocate(capacity: bufferLength)
		return data
	}
	
}
