# Android Firmware Transparency Log Proto Definitions
---

This directory contains the proto definitions required to communicate with an
AFTL server. Two (api.proto and aftl.proto) contain the definitions of the
protos needed to communicate with the AFTL Trillian personality. The remainder
are dependencies. The original repos and purpose for each proto file are as
follows:

* aftl.proto
   <!-- TODO(danielaustin): Add detailed message descriptions. -->
   Contains messages used by the AFTL frontend and the Trillian log.
* api.proto
   <!-- TODO(danielaustin): Add detailed message descriptions. -->
   Contains the messages to communicate through the AFTL personality.
* crypto/keyspb/keyspb.proto
   From https://github.com/google/trillian
   Dependency of trillian.proto
   Contains the PublicKey message definition used by Tree.
* crypto/sigpb/sigpb.proto
   From https://github.com/google/trillian
   Dependency of trillian.proto and aftl.proto
   For trillian.proto, contains the DigitallySigned message used by Tree and
   SignedEntryTimestamp. For aftl.proto, contains the DigitallySigned message
   used by SignedFirmwareInfo.
* trillian.proto
   From https://github.com/google/trillian
   Dependency of aftl.proto
   For aftl.proto, contains message definitions for SignedLogRoot.
* aftl_google/api/annotations.proto
   From https://github.com/googleapis/googleapis
   Used to get access to google.api.http options.
* aftl_google/api/http.proto
   From https://github.com/googleapis/googleapis
   Dependency of aftl_google/api/annotations.proto
   Contains the HttpRule message that extends MethodOptions.
* aftl_google/rpc/status.proto
   From https://github.com/googleapis/googleapis
