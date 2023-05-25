// swift-tools-version:5.6
import PackageDescription
let package = Package(
	name: "SwiftAWSSignatureV4"
	,platforms: [
        .macOS(.v10_15),
		.iOS(.v13),
		.watchOS(.v6),
		.tvOS(.v13),
	]
	,products: [
		.library(
			name: "SwiftAWSSignatureV4",
			targets: ["SwiftAWSSignatureV4"]),
		],
	dependencies:[
		.package(url: "https://github.com/apple/swift-crypto.git", from: "2.5.0"),
	]
	,targets:[
		.target(
			name: "SwiftAWSSignatureV4",
			dependencies: [
				.product(name: "Crypto", package: "swift-crypto"),
			]),
	  .testTarget(
		name: "SwiftAWSSignatureV4Tests",
		dependencies: [
			"SwiftAWSSignatureV4",
			.product(name: "Crypto", package: "swift-crypto"),
		]),
	  ]
	,swiftLanguageVersions:[.v5]
)
