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
