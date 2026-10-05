# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](Https://conventionalcommits.org) for commit guidelines.

<!-- changelog -->

## [v0.4.0](https://github.com/ash-project/ash_authentication_oauth2_server/compare/v0.3.1...v0.4.0) (2026-10-05)




### Features:

* protect more than one resource with one authorization server by [@maennchen](https://github.com/maennchen) [(#14)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/14)

### Bug Fixes:

* use Ash.Resource.Record.t() for OTP 29 compatibility by [@maennchen](https://github.com/maennchen) [(#15)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/15)

* reject client credentials from public clients by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* enforce the registered grant types at the token endpoint by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* omit the error code when registration has no initial access token by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* parse the Bearer scheme case-insensitively by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* return RFC 7009 errors from the revocation endpoint by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* report token endpoint server faults as 500 by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* keep error_description inside the OAuth character set by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* keep the redirect URI query when adding response parameters by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* default redirect_uri to the client's only registered URI by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* accept an authorize request without state by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* return invalid_scope for a missing scope at the authorize endpoint by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* validate client and redirect URI before other authorize errors by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* honour the scope parameter on refresh by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* consume an authorization code only after the token request passes by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* check refresh token state before its client and resource bindings by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* return invalid_client for an unknown client at the token endpoint by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* accept a token request without redirect_uri by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* return invalid_request for missing token request parameters by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

* return invalid_target for an unacceptable resource at the token endpoint by [@maennchen](https://github.com/maennchen) [(#13)](https://github.com/ash-project/ash_authentication_oauth2_server/pull/13)

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



