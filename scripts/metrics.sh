__LIB_STATE__
# --- request counts, per app, per minute ---------------------------------
if [ -f __ACCESS_LOG__ ]; then
	# Hostname -> app, from what each app declared. Read first so the awk over
	# the log can attribute as it goes rather than in a second pass.
	#
	# A wildcard entry (*.iframe.ormos.dev) is stored under its suffix, and a
	# hostname that matches nothing is counted for no app -- which is the honest
	# answer for a name pointed at this box by someone else.
	#
	# The apps are enumerated from komizo's own records, and the app NAME comes
	# from the record rather than from the directory it lives in. This used to
	# glob /srv/*/hostnames and take the basename, which was wrong twice over:
	# an app placed elsewhere with --app-dir was invisible, so its charts were
	# permanently empty; and an app whose directory did not match its name was
	# attributed to a bucket no app row matches, which looks identical. Every
	# other reader on the box was moved to the state files; this was the last
	# one left behind.
	{
		for _state in /var/lib/komizo/apps/*.env; do
			[ -f "$_state" ] || continue
			a="${_state##*/}"; a="${a%.env}"
			d="$(komizo_state "$_state" APP_DIR)"
			# shellcheck disable=SC2015 # both sides are tests; either failing means skip
			[ -n "$d" ] && [ -f "$d/hostnames" ] || continue
			# name [-> service]. The service is what the app says serves that
			# name; blank when it did not say, which is the honest default --
			# nothing on this box can work it out otherwise.
			sed 's/#.*//' "$d/hostnames" | tr -d '\r' | awk -v a="$a" 'NF {
				svc = ""
				if (NF >= 3 && $2 == "->") svc = $3
				printf "MAP\t%s\t%s\t%s\n", $1, a, svc
			}'
		done
		tail -c 4000000 __ACCESS_LOG__ 2>/dev/null
	} | awk -v from=__FROM__ -v to=__TO__ '
		/^MAP\t/ { split($0, m, "\t"); map[m[2]] = m[3]; svc[m[2]] = m[4]; next }

		{
			# The three fields that matter, pulled by pattern rather than by
			# position: this is JSON, and nothing promises key order.
			#
			# Whitespace after the colon is tolerated even though Caddy emits
			# none -- the cost is one character in a pattern, and the failure it
			# prevents is silent: every count reads zero and the chart is simply
			# flat, which looks exactly like no traffic.
			if (!match($0, /"ts":[ ]*[0-9.]+/)) next
			ts = substr($0, RSTART + 5, RLENGTH - 5) + 0

			# What the log actually covers, measured over every request line
			# in the tail -- INCLUDING the ones outside the asked-for range,
			# which is the whole point. It is the difference between "nothing
			# was served in this minute" and "nobody was writing this down
			# yet", and only the lines the range excludes can establish where
			# that boundary is.
			if (oldest == 0 || ts < oldest) oldest = ts
			if (ts > newest) newest = ts

			# The range, applied HERE rather than by the caller, so the answer
			# is small and roughly constant however wide a range is asked for
			# and however big the log has grown.
			if (ts < from || ts > to) next

			if (!match($0, /"host":[ ]*"[^"]+"/)) next
			host = substr($0, RSTART, RLENGTH)
			sub(/^"host":[ ]*"/, "", host); sub(/"$/, "", host)

			if (!match($0, /"status":[ ]*[0-9]+/)) next
			st = substr($0, RSTART + 9, RLENGTH - 9) + 0

			app = map[host]
			if (app == "") {
				# Not an exact name. Try the wildcard its parent would have
				# claimed: one label off the front, which is all Caddy allows.
				sub(/^[^.]+\./, "*.", host)
				app = map[host]
			}
			if (app == "") next
			s = svc[host]

			# Keyed by app AND the container the app said serves this name.
			# Summing over the second gives the app; filtering on it gives the
			# container. A name with no annotation lands under "", which is a
			# real bucket meaning "this app, container unstated" rather than a
			# missing one.
			bucket = int(ts / 60) * 60
			k = bucket "\t" app "\t" s
			seen[k] = 1
			if (st >= 500)      c5[k]++
			else if (st >= 400) c4[k]++
			else if (st >= 300) c3[k]++
			else                c2[k]++
		}

		END {
			# How far back the log itself goes. Without it every minute
			# before the log started charts as zero -- a confident claim that
			# nothing was served, drawn over a stretch nobody recorded.
			#
			# %.0f, not %d: these are unix timestamps, and BusyBox awk clamps
			# %d to 32 bits. They pass 2^31 in January 2038, at which point
			# every span would print negative and the reader -- correctly
			# refusing it -- would blank the charts on every box at once.
			if (oldest > 0) printf "mspan\t%.0f\t%.0f\n", oldest, newest
			for (k in seen) {
				split(k, f, "\t")
				# clamp-ok: the four %d are request counts for ONE minute.
				# The bucket and the app travel as %s, so nothing here is a
				# timestamp or a byte count and none of it approaches 2^31.
				printf "metric\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n",
					f[1], f[2], f[3], c2[k], c3[k], c4[k], c5[k]
			}
		}
	'
fi
