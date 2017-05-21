# SwiftAWSSignatureV4

AWS's signature version 4 in cross-platform Swift

Given a (mutable) `URLRequest`, sign with AWS Signature v4 using an instance of an `AWSAccount`, which would include your IAM credentials.

	`var request:URLRequest = ...`
	`let account:AWSAccount = ...`
	`request.sign(for:account)`

With a simple `Data` as the `.httpBody` of the request, no chunking is used. 

Appropriate date headers are added for you as part of the signing process.  You should add all other headers which are part of the service, but not speciic to signing before signing, because the signing process signs the headers.

To use chunking, provide an `InputStream` as the `.httpBodyStream` of the request, and / or provide a value for the chunk size (in bytes):

	`request.sign(for:account, chunkSize:32568)`

Signing without chunking has been tested on both macOS and Linux.  Chunking has only been tested on macOS.  Chunking is primarily useful for streams, which send data before reading the entire body in RAM.  Stream support may be altered or improve on Linux in the near future.

Depends on IBM's BlueCryptor for platform-independent hashing.
