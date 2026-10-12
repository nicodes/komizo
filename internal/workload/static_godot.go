package workload

import "strings"

// godotStaticRoute matches the reviewed single-threaded web gate. The policy
// pins the complete gate config independently; a changed export config needs
// renewed parity review before this profile can be used.
func godotStaticRoute(app, revision string) string {
	return strings.ReplaceAll(strings.ReplaceAll(`
	root * /srv/public/APP/REVISION
	@APP_legacy path /index.js* /index.wasm* /index.pck* /index.audio* /index.service.worker* /index.offline*
	respond @APP_legacy 404
	header {
		Cross-Origin-Opener-Policy "same-origin"
		Cross-Origin-Embedder-Policy "require-corp"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
		Content-Security-Policy "default-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
	}
	@APP_html path *.html /
	header @APP_html Cache-Control "no-cache, no-store, must-revalidate"
	@APP_gamefiles {
		path *.pck *.wasm *.js
		not path /releases/*
	}
	header @APP_gamefiles Cache-Control "no-cache, must-revalidate"
	@APP_packs path *.pck
	header @APP_packs Content-Type "application/octet-stream"
	@APP_json {
		path *.json
		not path /releases/*
	}
	header @APP_json Cache-Control "no-cache, must-revalidate"
	@APP_assets {
		path *.png *.jpg *.jpeg *.svg *.ico *.ttf *.woff *.woff2
		not path /releases/*
	}
	header @APP_assets Cache-Control "no-cache, must-revalidate"
	@APP_versioned path_regexp APP_versioned ^/releases/[0-9a-f]{64}/[^/]+$
	header @APP_versioned Cache-Control "public, max-age=31536000, immutable"
	file_server {
		precompressed br gzip
	}
	encode gzip {
		match {
			header Content-Type text/*
			header Content-Type application/json*
			header Content-Type application/javascript*
		}
	}
`, "APP", app), "REVISION", revision)
}

// Immutable exports retain gzip-only sidecars and apply the no-store contract
// to every mutable path, including missing routes. The reviewed gate hash and
// full image parity remain prerequisites to opting into this distinct layout.
func godotImmutableStaticRoute(app, revision string) string {
	prefix := godotStaticRoute(app, revision)
	prefix = prefix[:strings.Index(prefix, "\t@"+app+"_html path")]
	suffix := `
 @APP_mutable not path /releases/*
 header @APP_mutable Cache-Control "no-cache, no-store, must-revalidate"
 @APP_immutable path /releases/*
 header @APP_immutable Cache-Control "public, max-age=31536000, immutable"
 @APP_packs path *.pck
 header @APP_packs Content-Type "application/octet-stream"
 file_server {
  precompressed gzip
 }
`
	return prefix + strings.ReplaceAll(suffix, "APP", app)
}
