# Android Firmware Transparency Log Proto Definitions
---

This directory contains the proto definitions required to communicate with an
AFTL server. The original repos and purpose for each proto file are as
follows:

* api.proto
   Contains the messages to communicate with the AFTL personality.
* crypto/keyspb/keyspb.proto
   From https://github.com/google/trillian
   Dependency of trillian.proto
   Contains the PublicKey message definition used by Tree.
* crypto/sigpb/sigpb.proto
   From https://github.com/google/trillian
   Dependency of trillian.proto
   For trillian.proto, contains the DigitallySigned message used by Tree and
   SignedEntryTimestamp.
* trillian.proto
   From https://github.com/google/trillian
   Dependency of aftl.proto
   For aftl.proto, contains message definitions for SignedLogRoot.
