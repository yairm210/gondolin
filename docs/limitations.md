# Current Limitations

This page tracks the current limitations of Gondolin.  If you are evaluating
Gondolin for a production workflow, treat this as a "known gaps" checklist.

## No Snapshotting / Restore

Gondolin does not currently provide VM snapshotting (save/restore) for things
like:

* Capturing and restoring in-VM process state
* Saving a fully materialized disk/memory snapshot and resuming it later

Tracking issue: [#8](https://github.com/earendil-works/gondolin/issues/8)

**Note:** Gondolin can boot with an overlay root filesystem to avoid persisting
writes to the base image, but this is not a snapshot/restore mechanism.

## Adding Extra Packages Requires Building a New Image

The default guest image is intentionally minimal.  If you need additional
packages (for example: compilers, language runtimes, or extra system tools), you
currently need to build a custom guest image and point Gondolin at it.  This is
in some ways a consequence of the lack of snapshotting.

See [Custom Images](./custom-images.md).

## Only Alpine

The image builder currently only supports Alpine Linux.

## No HTTP/2 or HTTP/3 support

Gondolin's network mediation currently focuses on HTTP/1.x over plain TCP and
HTTPS via TLS interception.

As a result, HTTP/2 and HTTP/3 are not supported today.

## No QUIC or WebRTC support

Related to the lack of HTTP/3 support, QUIC is not supported.  Likewise WebRTC
is not supported.

This means software that relies on UDP-based application protocols (or generic
UDP connectivity) will not work in the default network model.

## Only QEMU (no krun)

Gondolin currently runs guests using QEMU.  There is no krun backend yet
but we're investigating it.

Tracking issue: [#7](https://github.com/earendil-works/gondolin/issues/7)

## No Windows support

The host side of Gondolin is currently supported on macOS and Linux.
