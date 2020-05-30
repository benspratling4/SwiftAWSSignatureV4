// swift-tools-version:5.2
import PackageDescription
let package = Package(
	name: "SwiftAWSSignatureV4",
	products: [
		.library(
			name: "SwiftAWSSignatureV4",
			targets: ["SwiftAWSSignatureV4"]),
		],
	dependencies:[
		// .package(url:"https://github.com/IBM-Swift/BlueCryptor.git", .upToNextMajor(from: "1.0.0"))
        .package(name: "Cryptor", url: "https://github.com/IBM-Swift/BlueCryptor.git", from: "1.0.0")
	],
	targets:[
		.target(
			name: "SwiftAWSSignatureV4",
			dependencies: ["Cryptor"]),
	  .testTarget(
		name: "SwiftAWSSignatureV4Tests",
		dependencies: ["SwiftAWSSignatureV4"]),
	  ],
	swiftLanguageVersions:[.v4,.v5]
)


// /Users/chris/Desktop/Apps/repos/SwiftAWSSignatureV4/Package.swift: dependency 'Cryptor' in target 'SwiftAWSSignatureV4' requires explicit declaration; provide the name of the package dependency with '.package(name: "Cryptor", url: "https://github.com/IBM-Swift/BlueCryptor.git", from: "1.0.0")'
