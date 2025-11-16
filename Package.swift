// swift-tools-version:6.2
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
			targets: ["SwiftAWSSignatureV4"]
		),
	],
	traits: [
		.default(enabledTraits: [
			"Apple",
			"HTTPTypes",
		]),
		.init(
			name: "Apple",
			description:"On Apple platforms, support for URLRequest is included",
		),
		.init(
			name: "HTTPTypes",
			description: "On platforms which use the server-side common currency library HTTPTypes",
		),
	],
	dependencies:[
		.package(url: "https://github.com/apple/swift-crypto.git",  "2.5.0"..<"5.0.0"),
		.package(url:"https://github.com/apple/swift-http-types.git", from:"1.5.0"),
	]
	,targets:[
		.target(
			name: "SwiftAWSSignatureV4",
			dependencies: [
				.product(name: "Crypto", package: "swift-crypto"),
				.product(name: "HTTPTypes", package: "swift-http-types", condition: .when(traits:[ "HTTPTypes"])),
			]
		),
		
		.testTarget(
			name: "SwiftAWSSignatureV4Tests",
			dependencies: [
				"SwiftAWSSignatureV4",
				.product(name: "Crypto", package: "swift-crypto"),
				.product(name: "HTTPTypes", package: "swift-http-types", condition: .when(traits: ["HTTPTypes"])),
			]
		),
		
	  ]
)
