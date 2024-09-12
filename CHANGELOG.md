# Released Notes

## v3.1.4 - (2024-09-12)

### Fixed

- Fixed `decrypt` method if a non hash is informed

-----------------------------------------------------------

## v3.1.3 - (2024-08-25)

### Added

- Added `AlgorithmEnum` enum

### Changed

- Changed default cost for bcrypt to 12
- Changed constants in `HashAlgorithm` to deprecated

-----------------------------------------------------------

## v3.1.2 - (2024-03-11)

### Fixed

- Fixed `SensitiveParameter` attribute on passwords

-----------------------------------------------------------

## v3.1.1 - (2024-02-18)

### Fixed

- Fixed `getPepper` method in `PepperTrait`

-----------------------------------------------------------

## v3.1.0 - (2024-01-31)

### Added

- Added method to benchmark cost
- Added microseconds in `usleep`
- Added set cost using `getOptimalBcryptCost` class
- Added `password_get_info` in `verifyHash`
- Added `paragonie/sodium_compat` component

### Fixed

- Fixed usleep in `verifyHash` method
- Fixed options at `password_hash`

## Removed

- Removed `HashException` class

-----------------------------------------------------------

## v3.0.0 - (2023-11-11)

### Added

- Added PHP 8.2 minimum version
- Added classes for encryption: OpenSSL and Sodium support
- Added `PepperTrait` trait to handle the peeper separately from the `SecuryPassword` class

### Changed

- Changed class structure

-----------------------------------------------------------

## v2.0.0 - (2022-09-21)

### Added

- Added support for PHP 8
- Added tests
- Added `_toString` in exception

### Changed

- Changed `createHash` and `verifyHash` methods

-----------------------------------------------------------

## v1.0.1 - (2021-10-29)

### Fixed

- Fixed HashAlgorithm

-----------------------------------------------------------

## v1.0.0 - (2021-10-12)

### Added

- Added settings in construct

### Changed

- Changed HashAlgorithm constant to public

### Fixed

- Fixed bugs

-----------------------------------------------------------

## v0.2.0 - (2021-04-20)

### Changed

- Changed `needsHash` method

-----------------------------------------------------------
## v0.1.1 - (2021-04-17)

### Added

- Added license

-----------------------------------------------------------
## v0.1.0 - (2021-04-17)

### Added

- Added project
