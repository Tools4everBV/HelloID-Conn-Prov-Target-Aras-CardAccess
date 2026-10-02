# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [2.0.0] - 23-09-2026

> [!IMPORTANT]
> The account reference changed from a number to a string. Existing implementations must verify their stored account references before upgrading.

### Changed

- Changed the account reference (`Badge`) to a string in `Create` and in the account and permission imports. This supports badge numbers outside the Int32 range.
- Added `Facility` to the `UpdateBadge` payloads in `Update`, `Enable`, `Disable`, `GrantPermission` and `RevokePermission`. Access groups are generic across facilities, so the `AccessGroups` calls are not filtered on `Facility`.

### Fixed

- Fixed the permission group import failing with `Value was either too large or too small for an Int32` when a badge number exceeds the Int32 range.
- Fixed the account and permission imports returning badges from other facilities. The `Facility` query parameter is not applied by `AllBadgeHolders`, so the badges are now filtered on `Facility` client side.
- Fixed the group grant payload so the added access group is always sent as a number in `AGNos`.
- Fixed `GrantPermission` and `RevokePermission` building `AGNos` from empty `AG#` slots. Only `AG#` properties with a value are used and duplicates are removed.

## [1.0.1] - 30-03-2026

### Changed

- Updated account lifecycle payloads for `Create`, `Enable` and `Disable` so `ActvDate` and `ExprDate` are no longer sent explicitly.
- Updated account `Update` flow to always include current `Enabled` status in the update body.
- Updated import endpoints to include `Facility` filtering when retrieving badge holders.
- Updated field mappings:
	- `lastName` now uses complex name-convention logic.
	- `facility` mapping now uses `Person.PrimaryContract.Employer.Name`.
- Updated permission API request configuration to consistently use `Headers`.
- Updated README remarks to document date behavior (`ActvDate`/`ExprDate`) and mandatory `Enabled` state preservation for `UpdateBadge` (update, permission grant, revoke).

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