# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](Https://conventionalcommits.org) for commit guidelines.

<!-- changelog -->

## [v0.3.1](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.3.0...v0.3.1) (2026-09-07)




### Bug Fixes:

* don't alias state-changing OAuth endpoints under /.well-known (CVE-2026-82754) by [@zachdaniel](https://github.com/zachdaniel)

* don't let shared caches store tenant-specific OAuth metadata (CVE-2026-82755) by [@zachdaniel](https://github.com/zachdaniel)

* escape tenant-derived values in WWW-Authenticate challenges (CVE-2026-82756) by [@zachdaniel](https://github.com/zachdaniel)

* reject IPv4-in-IPv6 and site-local forms the CIMD SSRF policy let through (CVE-2026-82757) by [@zachdaniel](https://github.com/zachdaniel)

* garbage-collect CIMD clients and require the ClientResource extension (CVE-2026-82753) by [@zachdaniel](https://github.com/zachdaniel)

* cache only validated CIMD documents and cap the metadata fetch at 5KB (CVE-2026-82753) by [@zachdaniel](https://github.com/zachdaniel)

* fail closed when a configured OAuth2 secret provider yields no usable secret (CVE-2026-82758) by [@zachdaniel](https://github.com/zachdaniel)

* allow localhost in the loopback redirect_uri port-wildcard exception (#5) by qamarq [(#5)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/5)

## [v0.3.0](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.2.2...v0.3.0) (2026-07-29)




### Features:

* support Client ID Metadata Documents, RFC 9207 iss, and insufficient_scope challenges by [@zachdaniel](https://github.com/zachdaniel)

## [v0.2.2](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.2.1...v0.2.2) (2026-05-31)




### Improvements:

* import formatter in installer by [@zachdaniel](https://github.com/zachdaniel)

## [v0.2.1](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.2.0...v0.2.1) (2026-05-31)




### Improvements:

* add spark.formatter logic by [@zachdaniel](https://github.com/zachdaniel)

## [v0.2.0](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.1.3...v0.2.0) (2026-05-29)




### Features:

* token cleanup, bulk chain revocation, and rotation telemetry by [@zachdaniel](https://github.com/zachdaniel)

## [v0.1.3](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.1.2...v0.1.3) (2026-05-27)




### Improvements:

* pass tenant to secret resolution by [@zachdaniel](https://github.com/zachdaniel)

## [v0.1.2](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.1.1...v0.1.2) (2026-05-27)




### Improvements:

* generate atomic safe resources by [@zachdaniel](https://github.com/zachdaniel)

## [v0.1.1](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.1.0...v0.1.1) (2026-05-26)




### Improvements:

* multitenancy support by [@zachdaniel](https://github.com/zachdaniel)

## [v0.1.0](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.1.0...v0.1.0) (2026-05-25)



