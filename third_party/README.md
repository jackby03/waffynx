# Third-party

Only one vendored project, and it is **not** a fork.

## nginx

- **Upstream:** https://github.com/nginx/nginx
- **Pinned to:** a release tag (`release-1.31.9` at the time of writing), tracked as a
  git submodule.
- **No local patches.** What gets compiled is chosen by `--with-*` / `--without-*`
  flags in [`deploy/docker/Dockerfile`](../deploy/docker/Dockerfile) and
  [`Makefile`](../Makefile), never by deleting or editing sources.

The Waffynx module lives in this repository at [`modules/ngx_waffynx/`](../modules/ngx_waffynx)
and is attached with `--add-module`. Nothing in this directory belongs to Waffynx.

Keeping the tree identical to upstream is deliberate: nginx terminates TLS and
serves every request, so a CVE in it is a CVE in Waffynx. With an unmodified
submodule, an update is a tag checkout plus one commit. The previous setup was a
hand-stripped fork (221 files deleted, 15 edited) which had to be re-stripped on
every release — and sat four releases behind while doing so.

Update with `make nginx-checkout` after changing the tag, or let Dependabot open
the PR. See [`SECURITY.md`](../SECURITY.md) for the triage rule: check the build
flags before assuming an advisory applies.

## open-appsec

**Not vendored.** It was previously present as a stripped submodule, but the chain
never ran: `WAFFYNX_REAL_ENGINE` was defined nowhere, so the compiled C++ bridge
was a stub, and the container built `appsec-bridge` with `CGO_ENABLED=0` while the
engine selected `basic-go` in-process. It added an 18 MB build dependency, a C++
toolchain and CMake patches for code that no request ever executed.

What remains is the **interface**, which is the part worth keeping: any process that
speaks the scorer protocol over a Unix socket can be plugged in through
`appsec.engine: open-appsec` plus `appsec.bridge_socket`
([`internal/appsec/bridge.go`](../internal/appsec/bridge.go)). Run the real engine
out of tree — as its own container or binary — and point Waffynx at it.

## Setup

```bash
git submodule update --init --recursive
```
