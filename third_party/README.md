# Third-Party Forked Projects

This directory contains **forked and heavily modified** versions of:

## nginx
- **Original**: https://github.com/nginx/nginx
- **Our fork**: https://github.com/jackby03/ngx_waffynx
- **Purpose**: Stripped down to core reverse proxy + HTTP/2 + stream modules.
  Removed: FastCGI, uwsgi, SCGI, mail proxy modules.
  Added: Native waffynx module for direct integration with policy engine.

## open-appsec
- **Original**: https://github.com/openappsec/openappsec
- **Our fork**: https://github.com/jackby03/appsec_waffynx
- **Purpose**: Stripped to core ML-based detection engine.
  Added: Plugin bridge for third-party AI model integration (future).
  Removed: Management UI and standalone agent components.

## Setup

```bash
# Initialize submodules after cloning waffynx
git submodule update --init --recursive

# Or manually clone the forks
cd third_party
git clone https://github.com/jackby03/ngx_waffynx.git nginx
git clone https://github.com/jackby03/appsec_waffynx.git open-appsec
```

## Build

See the main [Makefile](../Makefile) for build targets:

```bash
make nginx-build       # Builds the forked nginx
make build             # Builds Go components
make install-complete  # Full production install
```
