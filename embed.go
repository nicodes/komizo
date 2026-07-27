package main

import _ "embed"

// The server-side scripts, shipped over SSH and run as root on the box.
//
// They live under cli/ so that every Go file in this project is in one package
// -- go:embed cannot reach outside its own package directory, and having a
// second package at the repository root purely to hold an embed directive was
// the tail wagging the dog.
//
// They stay TEXT rather than being generated or compiled in: what runs as root
// on someone's server should be readable before it does, which is what
// `ncicd script` is for.

// AlpineScript sets an app up: Docker, the deploy account, its two privileged
// commands, the doas rules and the sshd restrictions.
//
//go:embed scripts/alpine.sh
var AlpineScript string

// AlpineRemoveScript tears one app back off. Separate from AlpineScript so that
// the thing which deletes can be read on its own, without hunting for a branch
// inside the thing that creates.
//
//go:embed scripts/alpine-remove.sh
var AlpineRemoveScript string

// AlpineInitScript prepares the server itself: the container runtime and the
// network apps share. Separate from AlpineScript because setting a server up
// and putting an app on it are different things -- a fresh box is either
// initialised or it is not, rather than becoming half-configured as a side
// effect of whichever app was added first.
//
//go:embed scripts/alpine-init.sh
var AlpineInitScript string

// AlpineProxyScript installs the one shared reverse proxy. Separate again
// because it is per-SERVER, not per-app: it takes no app name, creates no
// account, and re-running it is how you update Caddy or move it to another
// network.
//
//go:embed scripts/alpine-proxy.sh
var AlpineProxyScript string
