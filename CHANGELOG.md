# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.0.1] - 30-03-2026

### Changed

- Updated account lifecycle payloads for `Create`, `Enable` and `Disable` so `ActvDate` and `ExprDate` are no longer sent explicitly.
- Updated account `Update` flow to always include current `Enabled` status in the update body.
- Updated import endpoints to include `Facility` filtering when retrieving badge holders.
- Updated field mappings:
	- `lastName` now uses complex name-convention logic.
	- `facility` mapping now uses `Person.PrimaryContract.Employer.Name`.
- Updated permission API request configuration to consistently use `Headers`.

### Fixed

- Fixed permission import filtering to exclude the configured `NoAccessPermissionId`.
- Fixed group grant behavior to prevent duplicate permission assignments.
- Fixed group revoke behavior to skip API updates when the permission is not currently assigned.
- Fixed permission grant/revoke update payloads to include current `Enabled` status.

## [1.0.0] - 19-12-2025

This is the first official release of _HelloID-Conn-Prov-Target-Aras-CardAccess_. This release is based on template version _v3.2.0_.

### Added

### Changed

### Deprecated

### Removed