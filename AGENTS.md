# Go HAS CHANGED

Read the exact versioned docs before writing any code:

- Go 1.27: https://go.dev/doc/go1.27

# Application independence

Komizo is a reusable, application-agnostic host tool. Do not branch on particular
application names, GitHub accounts, domains, product services or business-specific
credential names. Application definitions belong in caller-supplied artifacts and
explicit operator-owned configuration. Shared behavior should depend on versioned
capabilities and resource requirements. Migrate existing consumers safely when
removing legacy special cases. Private fleet inventories, measurements and
operational documentation belong in `nicodes/docs`.

# Testing

Prove behavior at the lowest useful layer: unit tests for decisions and parsers,
local integration tests for component/process contracts, and minimal real-host
acceptance for kernel, installation and recovery boundaries. Keep exhaustive
input/error matrices below end-to-end tests. `make test` runs unit and integration
checks; `make artifact-check` verifies all published workstation targets.
`make portability` separately explores operating systems without published
archives. The fleet testing policy is canonical in private `nicodes/docs`.
