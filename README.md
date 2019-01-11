# Fingerprint

Fingerprint outputs various hash digests (and a checksum) of input files or a string. Uses the OpenSSL library to create the
hash digests. Output consists of the following:

01. crc32
02. MD4
03. MD5
04. RIPEMD160
05. SHA-1
06. SHA-224
07. SHA-256
08. SHA-384
09. SHA-512
10. Whirlpool

Example:

./fingerprint -s "The quick brown fox jumps over the lazy dog"

 Fingerprints for string "The quick brown fox jumps over the lazy dog"

     CRC32  414fa339
       MD4  1bee69a46ba811185c194762abaeae90
       MD5  9e107d9d372bb6826bd81d3542a419d6
 RIPEMD160  37f332f68db77bd9d7edd4969571ad671cf9dd3b
      SHA1  2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
    SHA224  730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525
    SHA256  d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
    SHA384  ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1
    SHA512  07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6
 WHIRLPOOL  b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35
