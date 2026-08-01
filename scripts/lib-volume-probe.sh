# shellcheck disable=SC2120 # called with an app by the monitor, without one by the sampler
volumes_all() {
	_only="${1:-}"
	command -v docker >/dev/null 2>&1 || return 0
	for _state in /var/lib/komizo/apps/*.env; do
		[ -f "$_state" ] || continue
		_app="${_state##*/}"; _app="${_app%.env}"
		[ -z "$_only" ] || [ "$_app" = "$_only" ] || continue
		_dir="$(komizo_state "$_state" APP_DIR)"
		# shellcheck disable=SC2015 # both sides are tests; either failing means skip
		[ -n "$_dir" ] && [ -f "$_dir/compose.yml" ] || continue
		_ids="$(docker compose -f "$_dir/compose.yml" --project-directory "$_dir" ps -aq 2>/dev/null)"
		[ -n "$_ids" ] || continue
		# shellcheck disable=SC2086 # deliberate word splitting: one container id per arg
		# service, volume name, and where it lives on the host. One line per
		# mount, so a volume shared by two containers appears under both.
		_pairs="$(docker inspect $_ids --format \
			'{{$s := index .Config.Labels "com.docker.compose.service"}}{{range .Mounts}}{{if eq .Type "volume"}}{{$s}}	{{.Name}}	{{.Source}}
{{end}}{{end}}' 2>/dev/null)"
		# Measured once per volume, then attributed. Two containers sharing one
		# volume must not make it count twice, and du is far too expensive to
		# run twice for the same answer.
		_sizes=""
		for _src in $(printf '%s\n' "$_pairs" | awk -F'\t' 'NF >= 3 && $3 != "" { print $3 }' | sort -u); do
			[ -d "$_src" ] || continue
			_sz="$(du -sxk "$_src" 2>/dev/null | awk '{ print $1 * 1024; exit }')"
			[ -n "$_sz" ] && _sizes="$_sizes$_src	$_sz
"
		done
		printf '%s\n' "$_pairs" | awk -F'\t' -v app="$_app" -v sz="$_sizes" '
			BEGIN {
				n = split(sz, L, "\n")
				for (i = 1; i <= n; i++) {
					split(L[i], p, "\t")
					if (p[1] != "") S[p[1]] = p[2]
				}
			}
			NF >= 3 && S[$3] != "" { printf "vol\t%s\t%s\t%s\t%s\n", app, $1, $2, S[$3] }'
	done
}
