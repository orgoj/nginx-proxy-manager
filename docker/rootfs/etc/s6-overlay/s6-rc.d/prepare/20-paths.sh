#!/command/with-contenv bash
# shellcheck shell=bash

set -e

log_info 'Checking paths ...'

# Ensure /data is mounted
if [ ! -d '/data' ]; then
	log_fatal '/data is not mounted! Check your docker configuration.'
fi
# Ensure /etc/letsencrypt is mounted
if [ ! -d '/etc/letsencrypt' ]; then
	log_fatal '/etc/letsencrypt is not mounted! Check your docker configuration.'
fi

# Create required folders
mkdir -p \
	/data/nginx \
	/data/nginx/global \
	/data/custom_ssl \
	/data/logs \
	/data/access \
	/data/nginx/default_host \
	/data/nginx/default_www \
	/data/nginx/error_pages \
	/data/nginx/proxy_host \
	/data/nginx/redirection_host \
	/data/nginx/stream \
	/data/nginx/dead_host \
	/data/nginx/temp \
	/data/letsencrypt-acme-challenge \
	/run/nginx \
	/tmp/nginx/body \
	/var/log/nginx \
	/var/lib/nginx/cache/public \
	/var/lib/nginx/cache/private \
	/var/cache/nginx/proxy_temp

touch /var/log/nginx/error.log || true
chmod 777 /var/log/nginx/error.log || true
chmod -R 777 /var/cache/nginx || true
chmod 644 /etc/logrotate.d/nginx-proxy-manager

# nginx has not been started yet, so any pid file here is stale. Remove it,
# otherwise a pid file owned by another user stops nginx starting as PUID:PGID
rm -f /run/nginx/nginx.pid

if [ ! -f /data/nginx/global/block-rules.conf ]; then
	cat >/data/nginx/global/block-rules.conf <<'EOF'
# Managed by Nginx Proxy Manager (block_rule). Do not edit by hand.
map $uri $npm_blk_acme {
	default 0;
	"~^/\.well-known/acme-challenge/" 1;
}
map $uri $npm_blk_internal {
	volatile;
	default 0;
	"~^/__npm_error/" 1;
}
map "" $npm_blk { default ""; }
map "" $npm_blk_static_rule { default ""; }
EOF
	chmod 644 /data/nginx/global/block-rules.conf
fi
