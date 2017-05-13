# SwiftAWSSignatureV4

AWS's signature version 4 in cross-platform Swift

Given a (mutable) `URLRequest`, sign with AWS Signature v4 using an instance of an `AWSAccount`, which would include your IAM credentials.

Depends on IBM's BlueCryptor for platform-independent hashing 
