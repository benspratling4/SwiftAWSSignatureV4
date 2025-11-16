@testable import SwiftAWSSignatureV4
import Testing
#if canImport(Foundation)
import Foundation
#else
import FoundationEssentials
#endif



@Suite
struct HexTests {
	
	@Test
	func testHexInts()throws {
		let cases:[(UInt64, String)] = [
			(0, "0000000000000000")
			,(1, "0000000000000001")
			,(65536, "0000000000010000")
			,(1147797409030816545, "0FEDCBA987654321")
		]
		
		for (int, string) in cases {
			try #require(int.bytesAsHex == string)
		}
	}
	
	@Test
	func testLowerCaseHex()throws {
		//hexBytes(uppercase
		
		let cases:[(Data, String)] = [
			(Data([0x00, 0x01, 0x02, 0x0e, 0xe0]), "0001020ee0"),
			//TODO: write more tests
//			,(1, "0000000000000001")
//			,(65536, "0000000000010000")
//			,(1147797409030816545, "0FEDCBA987654321")
		]
		
		for (int, string) in cases {
			try #require(int.hexBytes() == string)
		}
	}
	
	@Test
	func testUpperCaseHex()throws {
		//hexBytes(uppercase
		
		let cases:[(Data, String)] = [
			(Data([0x00, 0x01, 0x02, 0x0e, 0xe0]), "0001020EE0"),
			//TODO: write more tests
//			,(1, "0000000000000001")
//			,(65536, "0000000000010000")
//			,(1147797409030816545, "0FEDCBA987654321")
		]
		
		for (int, string) in cases {
			try #require(int.hexBytes(uppercase: true) == string)
		}
	}
	
	
}
