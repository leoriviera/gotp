# gotp

This is a project that implements the HMAC-Based One Time Password Algorithm (RFC 4226) and the Time-Based One-Time Password Algorithm (RFC 6238) in Go.

This is a learning project. It is terrible and inelegant code at the moment, but I'll most likely come back to it and fix it as I learn more go.

This project supports

- different hashing algorithms for HMAC, namely SHA1, SHA256, and SHA512
- different lengths for the one-time password, 6 and 8 digits
- 30 second and 60 second periods for TOTP

This project has no dependencies, only using functions included in Go's standard library. It also has tests, based on the test cases from both RFCs.

## TODO

- Trigger tests on GitHub Actions
