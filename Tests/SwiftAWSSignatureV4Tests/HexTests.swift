@testable import SwiftAWSSignatureV4
import XCTest

class HexTests : XCTestCase {
	
	func testHexInts() {
		let cases:[(UInt64, String)] = [
			(0, "0000000000000000")
			,(1, "0000000000000001")
			,(65536, "0000000000010000")
			,(1147797409030816545, "0FEDCBA987654321")
		]
		
		for (int, string) in cases {
			XCTAssertEqual(int.bytesAsHex, string)
		}
	}
	
	
	func testLowerCaseHex() {
		//hexBytes(uppercase
		
		let cases:[(Data, String)] = [
			(Data([0x00, 0x01, 0x02, 0x0e, 0xe0]), "0001020ee0"),
			//TODO: write more tests
//			,(1, "0000000000000001")
//			,(65536, "0000000000010000")
//			,(1147797409030816545, "0FEDCBA987654321")
		]
		
		for (int, string) in cases {
			XCTAssertEqual(int.hexBytes(), string)
		}
	}

	func testUpperCaseHex() {
		//hexBytes(uppercase
		
		let cases:[(Data, String)] = [
			(Data([0x00, 0x01, 0x02, 0x0e, 0xe0]), "0001020EE0"),
			//TODO: write more tests
//			,(1, "0000000000000001")
//			,(65536, "0000000000010000")
//			,(1147797409030816545, "0FEDCBA987654321")
		]
		
		for (int, string) in cases {
			XCTAssertEqual(int.hexBytes(uppercase: true), string)
		}
	}
	
	
}
