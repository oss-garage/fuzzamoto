#!/bin/bash
# Build the guest initramfs for fuzzamoto's bedrock backend.
#
# Usage: ./build-initramfs.sh <scenario> <bitcoind> <init> <out.cpio.gz>
set -euo pipefail

if [ $# -ne 4 ]; then
    sed -n '2,8p' "$0" >&2
    exit 2
fi
SCENARIO=$1; BITCOIND=$2; INIT=$3; OUT=$(realpath -m "$4")

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

install -m 0755 "$INIT" "$root/init"
install -m 0755 "$SCENARIO" "$root/scenario"
install -m 0755 "$BITCOIND" "$root/bitcoind"

# Copy the shared libraries.
for bin in "$SCENARIO" "$BITCOIND"; do
    interpreter=$(readelf -p .interp "$bin" | awk '/\/ld/ {print $NF}')
    [ -z "$interpreter" ] || install -D -m 0755 "$interpreter" "$root$interpreter"
    lddtree "$bin" | tail -n +2 | while read -r line; do
        case "$line" in *"=>"*) ;; *) continue ;; esac
        path=${line#*=> }
        path=${path%% *}
        [ -f "$path" ] || continue
        dest="$root${path}"
        mkdir -p "$(dirname "$dest")"
        [ -f "$dest" ] || install -m 0755 "$path" "$dest"
    done
done

( cd "$root" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > "$OUT" )
echo "$OUT: $(du -h "$OUT" | cut -f1) ($(find "$root" -type f | wc -l) files)"
