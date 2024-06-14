All notable changes to this project will be documented in this file.

## 0.3.0 - 2024-06-17
This release adds support for portfolio solving with a configurable timeout.

### Breaking Changes:
- None

### New features
- Added support for running multiple solvers in parallel. 
- Added configurable timeout to address the issue of varying time the solver takes to solve depending on the underlying machines on which it is running

### Bug fixes:
- None

## 0.2.0 - 2023-10-31 
This second release adds support for variables in policies, also referred to as "policy templates".

### Breaking Changes:
- None

### New features
- Add support for using CloudSec variables in the values of components in policies. This feature allows users
to define entire sets of policies in a concise way.

- Add support for running CloudSec without all SMT solvers installed. The library now attempts to install each library and catches failures (Issue #3).

- Added Dockerfile to build ARM64 image for the Cloudsec library

### Bug fixes:
- None


## 0.1.0 - 2023-01-30
Initial release of the CloudSec library with support for z3 and cvc5 on x86.

### Breaking Changes:
- None

### New features
- None

### Bug fixes:
- None
