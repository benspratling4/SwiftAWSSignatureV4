// swift-tools-version:5.0
import PackageDescription
let package = Package(
	name: "SwiftAWSSignatureV4"
	,platforms: [
        .macOS(.v10_11)
	]
	,products: [
		.library(
			name: "SwiftAWSSignatureV4",
			targets: ["SwiftAWSSignatureV4"]),
		],
	dependencies:[
		.package(url:"https://github.com/IBM-Swift/BlueCryptor.git", from:"1.0.32")
	]
	,targets:[
		.target(
			name: "SwiftAWSSignatureV4",
			dependencies: ["Cryptor"]),
	  .testTarget(
		name: "SwiftAWSSignatureV4Tests",
		dependencies: ["SwiftAWSSignatureV4"]),
	  ]
	,swiftLanguageVersions:[.v5]
)
