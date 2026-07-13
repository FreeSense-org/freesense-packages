# FreeSense Packages

This repository contains the optional packages shown in the FreeSense package
manager and the metadata used to publish their independent binary repository.

The package repository is versioned by the FreeSense compatibility train (for
example `1.1`) and is rebuilt only when package definitions, package policy, or
their relevant upstream dependency snapshot changes. Rapid operating-system
development does not rebuild these packages.

FreeSense system/runtime ports live in
[`freesense-system-ports`](https://github.com/FreeSense-org/freesense-system-ports).
The upstream FreeBSD ports tree remains an external build input.

Package ports use the `FreeSense-pkg-*` naming convention and
`Mk/bsd.freesense-package.mk`. System-image ports must not be added here; CI
enforces this boundary.
