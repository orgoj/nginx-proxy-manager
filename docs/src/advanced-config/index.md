---
outline: deep
---

# Advanced Configuration

## Running processes as a user/group

By default, the services (nginx etc) will run as `root` user inside the docker container.
You can change this behaviour by setting the following environment variables.
Not only will they run the services as this user/group, they will change the ownership
on the `data` and `letsencrypt` folders at startup.

```yml
services:
  app:
    image: 'jc21/nginx-proxy-manager:{{VERSION}}'
    environment:
      PUID: 1000
      PGID: 1000
    # ...
```

This may have the side effect of a failed container start due to permission denied trying
to open port 80 on some systems. The only course to fix that is to remove the variables
and run as the default root user.

## Best Practice: Use a Docker network

For those who have a few of their upstream services running in Docker on the same Docker
host as NPM, here's a trick to secure things a bit better. By creating a custom Docker network,
you don't need to publish ports for your upstream services to all of the Docker host's interfaces.

Create a network, ie "scoobydoo":

```bash
docker network create scoobydoo
```

Then add the following to the `docker-compose.yml` file for both NPM and any other
services running on this Docker host:

```yml
networks:
  default:
    external: true
    name: scoobydoo
```

Let's look at a Portainer example:

```yml
services:

  portainer:
    image: portainer/portainer
    privileged: true
    volumes:
      - './data:/data'
      - '/var/run/docker.sock:/var/run/docker.sock'
    restart: unless-stopped

networks:
  default:
    external: true
    name: scoobydoo
```

Now in the NPM UI you can create a proxy host with `portainer` as the hostname,
and port `9000` as the port. Even though this port isn't listed in the docker-compose
file, it's "exposed" by the Portainer Docker image for you and not available on
the Docker host outside of this Docker network. The service name is used as the
hostname, so make sure your service names are unique when using the same network.

## Docker Healthcheck

The `Dockerfile` that builds this project does not include a `HEALTHCHECK` but you can opt in to this
feature by adding the following to the service in your `docker-compose.yml` file:

```yml
healthcheck:
  test: ["CMD", "/usr/bin/check-health"]
  interval: 10s
  timeout: 3s
```

## Docker File Secrets

This image supports the use of Docker secrets to import from files and keep sensitive usernames or passwords from being passed or preserved in plaintext.

You can set any environment variable from a file by appending `__FILE` (double-underscore FILE) to the environmental variable name.

```yml
secrets:
  # Secrets are single-line text files where the sole content is the secret
  # Paths in this example assume that secrets are kept in local folder called ".secrets"
  DB_ROOT_PWD:
    file: .secrets/db_root_pwd.txt
  MYSQL_PWD:
    file: .secrets/mysql_pwd.txt

services:
  app:
    image: 'jc21/nginx-proxy-manager:{{VERSION}}'
    restart: unless-stopped
    ports:
      # Public HTTP Port:
      - '80:80'
      # Public HTTPS Port:
      - '443:443'
      - '443:443/udp'
      # Admin Web Port:
      - '81:81'
    environment:
      # These are the settings to access your db
      DB_MYSQL_HOST: "db"
      DB_MYSQL_PORT: 3306
      DB_MYSQL_USER: "npm"
      # DB_MYSQL_PASSWORD: "npm"  # use secret instead
      DB_MYSQL_PASSWORD__FILE: /run/secrets/MYSQL_PWD
      DB_MYSQL_NAME: "npm"
      # If you would rather use Sqlite, remove all DB_MYSQL_* lines above
      # Uncomment this if IPv6 is not enabled on your host
      # DISABLE_IPV6: 'true'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
    secrets:
      - MYSQL_PWD
    depends_on:
      - db

  db:
    image: 'linuxserver/mariadb'
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD__FILE: /run/secrets/DB_ROOT_PWD
      MYSQL_DATABASE: 'npm'
      MYSQL_USER: 'npm'
      MYSQL_PASSWORD__FILE: /run/secrets/MYSQL_PWD
      TZ: 'Australia/Brisbane'
    volumes:
      - ./mariadb:/config
    secrets:
      - DB_ROOT_PWD
      - MYSQL_PWD
```


## Disabling IPv6

On some Docker hosts IPv6 may not be enabled. In these cases, the following message may be seen in the log:

> Address family not supported by protocol

The easy fix is to add a Docker environment variable to the Nginx Proxy Manager stack:

```yml
    environment:
      DISABLE_IPV6: 'true'
```

## Disabling IP Ranges Fetch

By default, NPM fetches IP ranges from CloudFront and Cloudflare during application startup. In environments with limited internet access or to speed up container startup, this fetch can be disabled:

```yml
    environment:
      IP_RANGES_FETCH_ENABLED: 'false'
```

## Custom Nginx Configurations

If you are a more advanced user, you might be itching for extra Nginx customizability.

NPM has the ability to include different custom configuration snippets in different places.

You can add your custom configuration snippet files at `/data/nginx/custom` as follow:

 - `/data/nginx/custom/root_top.conf`: Included at the top of nginx.conf
 - `/data/nginx/custom/root.conf`: Included at the very end of nginx.conf
 - `/data/nginx/custom/http_top.conf`: Included at the top of the main http block
 - `/data/nginx/custom/http.conf`: Included at the end of the main http block
 - `/data/nginx/custom/events.conf`: Included at the end of the events block
 - `/data/nginx/custom/stream.conf`: Included at the end of the main stream block
 - `/data/nginx/custom/server_proxy.conf`: Included at the end of every proxy server block
 - `/data/nginx/custom/server_redirect.conf`: Included at the end of every redirection server block
 - `/data/nginx/custom/server_stream.conf`: Included at the end of every stream server block
 - `/data/nginx/custom/server_stream_tcp.conf`: Included at the end of every TCP stream server block
 - `/data/nginx/custom/server_stream_udp.conf`: Included at the end of every UDP stream server block
 - `/data/nginx/custom/server_dead.conf`: Included at the end of every 404 server block

Every file is optional.

## Custom Error Pages

All proxy, redirection and 404 hosts and the default site share one set of error pages for
errors that Nginx itself generates (400, 401, 403, 404, 405, 408, 413, 414, 429, 500, 502, 503, 504),
for example when a backend is down or an access list denies the request. Errors returned by
a backend are passed through unchanged.

Place your own pages in `/data/nginx/error_pages`; no restart or rebuild is needed:

 - `/data/nginx/error_pages/<status>.html` (e.g. `502.html`): used for that status
 - `/data/nginx/error_pages/error.html`: used for every status without its own page

Pages are processed with [SSI](https://nginx.org/en/docs/http/ngx_http_ssi_module.html),
so `<!--# echo var="status" -->` prints the status code. An `error_page` directive in a host's
advanced configuration or in a `server_*.conf` snippet takes precedence for its status codes.


## X-FRAME-OPTIONS Header

You can configure the [`X-FRAME-OPTIONS`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) header
value by specifying it as a Docker environment variable. The default if not specified is `deny`.

```yml
  ...
  environment:
    X_FRAME_OPTIONS: "sameorigin"
  ...
```

## Customising logrotate settings

By default, NPM rotates the access- and error logs weekly and keeps 4 and 10 log files respectively.
Depending on the usage, this can lead to large log files, especially access logs.
You can customise the logrotate configuration through a mount (if your custom config is `logrotate.custom`):

```yml
  volumes:
    ...
    - ./logrotate.custom:/etc/logrotate.d/nginx-proxy-manager
```

For reference, the default configuration can be found [here](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/docker/rootfs/etc/logrotate.d/nginx-proxy-manager).

### Scheduled rotation of your own logs

Every `*.conf` file in `/data/logrotate.d/` is rotated once a day at `LOGROTATE_TIME`
(`HH:MM`, default `00:05`) in the container time zone (`TZ`, default UTC), with state in
`/data/logrotate/status`. logrotate runs as root here, or as `PUID:PGID` when `PUID` is set
(then `postrotate` scripts cannot signal nginx; use `copytruncate`), so the files must be
owned by root or that user and not group- or world-writable. A group in `create` must exist in the container; to keep
a host group, give the log directory that group and mode `2755` (setgid, not group-writable,
or logrotate skips it) and use `create <mode>` without owner.

```yml
    environment:
      TZ: 'Europe/Prague'
      LOGROTATE_TIME: '00:05'
```

## Editing custom files in the admin UI

Administrators can list, create, edit and delete the `*.conf` files in `/data/nginx/custom/`
and `/data/logrotate.d/` on the **Custom Files** page. Saving or deleting an nginx file runs
`nginx -t`; on failure the previous file is restored and the error is shown, otherwise nginx
reloads. A logrotate file is checked with `logrotate -d` (errors and warnings refuse it) and
written with mode `0644`. Only the fixed names above are loaded by nginx; include other files
from them yourself.

## Proxy host caching

Each proxy host has three cache options:

- **Cache Assets** caches static files (css, js, images, fonts) only.
- **Edge Micro-Cache** caches every response briefly and serves a stale copy while the
  backend fails or the entry is updated. It also covers the assets.
- **Public static paths** (default `/static/`) are URI prefixes, separated by spaces, whose
  cache is shared with clients that send cookies.

Both cache modes work at server level, so access lists, basic auth and custom locations
apply to cached files as well.

Responses are never stored when they:

- carry `Set-Cookie` or `Vary: *`;
- have status 401, 403 or 5xx;
- answer a request with `Authorization` or `Cookie`.

Requests with a `Cookie` read the cache only under the public paths. With Cache Assets
alone, the backend's `Cache-Control`/`Expires` are honoured: `private`, `no-store` and
`no-cache` are never stored, and the backend's lifetime wins. Cookie requests under the
public paths may also fill the cache.

The Edge Micro-Cache stores anonymous responses for a short fixed time, even when the
backend marks them `private`/`no-store`. Many applications do that for every page, and a
request without cookies or credentials gets no personal content. The cache key contains the
domain and changes whenever the host is saved.

Lifetimes (nginx time values; with Cache Assets alone, they apply only when the backend sends
no lifetime):

```yml
    environment:
      NPM_CACHE_EDGE_VALID_200: '2s'
      NPM_CACHE_EDGE_VALID_301_302: '2m'
      NPM_CACHE_EDGE_VALID_404: '5m'
      NPM_CACHE_ASSET_VALID_200: '30m'
      NPM_CACHE_ASSET_VALID_404: '1m'
```

The cache status of each request is the field after the timestamp in the host access log.
A page that sets a cookie for anonymous visitors is never cached. That is intended: the fix
belongs in the application.

To move caching from your own custom includes to these options:

1. Remove the `proxy_cache*` lines from `/data/nginx/custom/server_proxy.conf`.
2. Preview the changes with `docker exec <npm> sh -c 'cd /app && node scripts/cache-migrate
   --edge-all --exclude <domain> --public-paths <domain>=/static/,/media/'` (a dry run).
3. Repeat the command with `--apply` to write the changes, regenerate all proxy hosts and
   reload nginx.

## Only custom access logs

With `DISABLE_ACCESS_LOG` set, NPM writes no access logs of its own (http, stream, hosts,
default and fallback servers, and asset locations no longer switch logging off). Define your
own `access_log` in `/data/nginx/custom/http_top.conf` and every host inherits it. Error logs
and the admin UI are unchanged. Existing host configs follow the setting on every start.

```yml
    environment:
      DISABLE_ACCESS_LOG: 'true'
```

## Enabling the geoip2 module

To enable the geoip2 module, you can create the custom configuration file `/data/nginx/custom/root_top.conf` and include the following snippet:

```
load_module /usr/lib/nginx/modules/ngx_http_geoip2_module.so;
load_module /usr/lib/nginx/modules/ngx_stream_geoip2_module.so;
```

## Auto Initial User Creation

Setting these environment variables will create the default user on startup, skipping the UI first user setup screen:

```yml
    environment:
      INITIAL_ADMIN_EMAIL: my@example.com
      INITIAL_ADMIN_PASSWORD: mypassword1
```

## Disable Nginx Resolver

On startup, we generate a resolvers directive for Nginx unless this is defined:

```yml
    environment:
      DISABLE_RESOLVER: true
```

In this configuration, all DNS queries performed by Nginx will fall to the `/etc/hosts` file
and then the `/etc/resolv.conf`.


## Changing the Admin UI port from 81 to something else

First, add an env var to your docker compose file:
```yml
    environment:
      NPM_ADMIN_PORT: '8000'
```

And you'll probably want to expose that port as well

```yml
    ports:
      - '8000:8000'
```

Then you'll be able to access admin UI at `http://localhost:8000`
