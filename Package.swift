// swift-tools-version:4.0
import PackageDescription
let package = Package(
	name: "SwiftAWSSignatureV4",
	products: [
		.library(
			name: "SwiftAWSSignatureV4",
			targets: ["SwiftAWSSignatureV4"]),
		],
	dependencies:[
		.package(url:"https://github.com/IBM-Swift/BlueCryptor.git", from:"1.0.0")
	],
	targets:[
		.target(
			name: "SwiftAWSSignatureV4",
			dependencies: ["Cryptor"]),
	  .testTarget(
		name: "SwiftAWSSignatureV4Tests",
		dependencies: ["SwiftAWSSignatureV4"]),
	  ],
	swiftLanguageVersions:[3,4]
)
