# Changelog

All notable changes to this project will be documented in this file.

## [1.15.1-alpha.6] - 2026-10-26

### Fixed

- `createCertificateRequest` no longer throws an unhandled `TypeError` when `notBefore` / `notAfter` are omitted or passed as RFC3339 strings. Both fields now accept a `Date` or an RFC3339 string, are only sent to the CA when provided, and invalid values fail fast with a descriptive error in both KRM and gRPC modes.

## [1.15.1-alpha.5] - 2026-08-19

### Fixed

- Improved instructions for standalone binary compilation and file transfer for remote test environments.

## [1.15.1-alpha.4] - 2026-06-23

### Added

- Added native KRM support for certificate revocation (`createRevokeCertificateRequest` using `certificateRequestRef`)
- Added KRM CRUD operations for revocation requests (`getRevokeCertificateRequest`, `listRevokeCertificateRequests`, `deleteRevokeCertificateRequest`)
- Added gRPC support for certificate revocation (`createRevokeCertificateRequest`)

## [1.15.1-alpha.3] - 2026-06-23

### Added

- Added gRPC support (`useGrpc: true`) to bypass KRM in `createCertificateRequest` for direct, high-performance dataplane access
- Enabled HTTPS keep-alive connection pooling to improve QPS

## [1.15.0] - 2025-07-22

### Added

- Supported certificateTemplate and subjectOverride for the Big Bear release of CAS
- Supported getCertificateAuthority to fetch the CA information

### Fixed

- Updated certificateRequest creation logic to fail fast on permanent errors

## [1.0.0] - 2025-06-02

### Added

- Supported STS token auth and auto refresh before expiry
- Supported certificateRequest CRUD operations
