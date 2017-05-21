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
	
}
