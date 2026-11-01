#!/command/with-contenv bash
# shellcheck shell=bash

# This command reads the `DISABLE_ACCESS_LOG` env var and will either disable
# or re-enable every NPM access_log (to /data/logs, and `access_log off`) in
# all generated nginx configs. With it disabled, the only access log is the
# one a user defines in /data/nginx/custom (inherited from http level), which
# is never modified here. The backend applies the same rule to configs it
# generates at runtime (internal/nginx.js).

set -e

log_info 'Access log ...'

MARKER='#DISABLE_ACCESS_LOG# '

if [ "$(is_true "${DISABLE_ACCESS_LOG:-}")" = '1' ]; then
	echo "Disabling NPM access logs"
	SED_REGEX="s/^(\s*)(access_log\s+(\/data\/logs\/|off;))/\1${MARKER}\2/"
else
	echo "Enabling NPM access logs"
	SED_REGEX="s/^(\s*)${MARKER}access_log/\1access_log/"
fi

process_folder () {
	local FILE TMPFILE

	find "$1" -path /data/nginx/custom -prune -o -type f -name '*.conf' -print | while read -r FILE
	do
		if ! grep -Eq 'access_log' "$FILE"; then
			continue
		fi
		TMPFILE="${FILE}.tmp"
		if is_mounted "${FILE}"; then
			echo "WARNING: skipping ${FILE} — mounted file" >&2
		elif sed -E "$SED_REGEX" "$FILE" > "$TMPFILE" && [ -s "$TMPFILE" ]; then
			echo "- ${FILE}"
			mv "$TMPFILE" "$FILE"
		else
			echo "WARNING: skipping ${FILE} — sed produced empty output" >&2
			rm -f "$TMPFILE"
		fi
	done

	# ensure the files are still owned by the npm user
	chown -R "$PUID:$PGID" "$1"
}

process_folder /etc/nginx/conf.d
process_folder /data/nginx
