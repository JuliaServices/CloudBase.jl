
# CloudBase

[![CI](https://github.com/JuliaServices/CloudBase.jl/workflows/CI/badge.svg)](https://github.com/JuliaServices/CloudBase.jl/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/JuliaServices/CloudBase.jl/branch/master/graph/badge.svg)](https://codecov.io/gh/JuliaServices/CloudBase.jl)
[![deps](https://juliahub.com/docs/CloudBase/deps.svg)](https://juliahub.com/ui/Packages/CloudBase/HHBkp?t=2)
[![version](https://juliahub.com/docs/CloudBase/version.svg)](https://juliahub.com/ui/Packages/CloudBase/HHBkp)
[![pkgeval](https://juliahub.com/docs/CloudBase/pkgeval.svg)](https://juliahub.com/ui/Packages/CloudBase/HHBkp)

*A simple, yet comprehensive foundation for interacting with common cloud providers in Julia.*

Current provider status on `main`:
- AWS: mature
- Azure: mature
- GCP: request client supports explicit bearer tokens, `service_account`, `authorized_user`, and file/url-based `external_account` credentials, plus metadata-server credentials and Cloud Storage XML HMAC interop via `AWS4-HMAC-SHA256`

## Installation

The package is registered in the [`General`](https://github.com/JuliaRegistries/General) registry and so can be installed at the REPL with `] add CloudBase`.

## Documentation

- [**STABLE**][docs-stable-url] &mdash; **most recently tagged version of the documentation.**
- [**LATEST**][docs-latest-url] &mdash; *in-development version of the documentation.*

## Project Status

The package is tested against Julia `1.6`, current stable release, and nightly on Linux.
Default CI stays fully local/mock-based. There is also an opt-in live GCP smoke test in `test/runtests.jl` that exercises one real object write/read/delete round-trip against an existing bucket.

Live test environment:
- `CLOUDBASE_RUN_GCP_LIVE_TESTS=1`
- `CLOUDBASE_GCP_LIVE_BUCKET=<existing-bucket>`
- One credential option:
  - `CLOUDBASE_GCP_LIVE_ACCESS_TOKEN=<token>`
  - `CLOUDBASE_GCP_LIVE_CREDENTIALS_FILE=<adc-or-service-account-file>`
  - `GOOGLE_APPLICATION_CREDENTIALS=<adc-or-service-account-file>`
  - `CLOUDBASE_GCP_LIVE_HMAC_ACCESS_ID=<id>` and `CLOUDBASE_GCP_LIVE_HMAC_SECRET=<secret>`
- Optional: `CLOUDBASE_GCP_LIVE_QUOTA_PROJECT=<project>`

The live credential needs object create/get/delete access on the target bucket.

## Contributing and Questions

Contributions are very welcome, as are feature requests and suggestions. Please open an
[issue][issues-url] if you encounter any problems or would just like to ask a question.

[docs-latest-img]: https://img.shields.io/badge/docs-latest-blue.svg
[docs-latest-url]: https://juliaservices.github.io/CloudBase.jl/latest

[docs-stable-img]: https://img.shields.io/badge/docs-stable-blue.svg
[docs-stable-url]: https://juliaservices.github.io/CloudBase.jl/stable

[ci-img]: https://github.com/JuliaServices/CloudBase.jl/workflows/CI/badge.svg
[ci-url]: https://github.com/JuliaServices/CloudBase.jl/actions?query=workflow%3ACI+branch%3Amaster

[codecov-img]: https://codecov.io/gh/JuliaServices/CloudBase.jl/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/JuliaServices/CloudBase.jl

[issues-url]: https://github.com/JuliaServices/CloudBase.jl/issues
