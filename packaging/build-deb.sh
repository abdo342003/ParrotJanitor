#!/usr/bin/env bash
#
# Build a Debian binary package for Parrot Janitor.
#
#   ./packaging/build-deb.sh                     # -> parrot-janitor_1.0.0-1_all.deb
#   VERSION=1.1.0 ./packaging/build-deb.sh       # bump the upstream version
#   OUTDIR=/tmp ./packaging/build-deb.sh         # put the .deb somewhere else
#
# No debhelper required — just dpkg-deb, fakeroot and (optionally) lintian.
set -euo pipefail

pkg="parrot-janitor"
version="${VERSION:-1.0.0}"
revision="${REVISION:-1}"
arch="${ARCH:-all}"

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
src="$(cd -- "$(dirname -- "$here")" && pwd)"
outdir="${OUTDIR:-$src}"
outfile="$outdir/${pkg}_${version}-${revision}_${arch}.deb"

die() { echo "error: $*" >&2; exit 1; }

command -v dpkg-deb  >/dev/null || die "dpkg-deb not found"
[ -f "$src/parrotjanitor.py" ]  || die "missing $src/parrotjanitor.py"
[ -f "$here/control.in" ]       || die "missing $here/control.in"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
root="$stage/$pkg"

install -d \
    "$root/DEBIAN" \
    "$root/usr/bin" \
    "$root/usr/lib/$pkg" \
    "$root/usr/share/applications" \
    "$root/usr/share/doc/$pkg" \
    "$root/usr/share/man/man1" \
    "$root/usr/share/icons/hicolor/scalable/apps" \
    "$root/usr/share/icons/hicolor/128x128/apps" \
    "$root/usr/share/icons/hicolor/256x256/apps"

# ---- payload ------------------------------------------------------------
install -m755 "$src/parrotjanitor.py" "$root/usr/lib/$pkg/parrotjanitor.py"
ln -s "../lib/$pkg/parrotjanitor.py" "$root/usr/bin/$pkg"

install -m644 "$here/parrot-janitor.desktop" "$root/usr/share/applications/$pkg.desktop"
install -m644 "$src/parrot-janitor.svg" \
              "$root/usr/share/icons/hicolor/scalable/apps/$pkg.svg"

# PNG fallbacks for icon themes that ignore hicolor/scalable. Best effort —
# the scalable SVG alone is enough for both Qt and GTK icon themes.
if python3 - "$src/parrot-janitor.svg" "$root" "$pkg" >/dev/null 2>&1 <<'PY'
import sys
import gi
gi.require_version('GdkPixbuf', '2.0')
from gi.repository import GdkPixbuf
svg, root, pkg = sys.argv[1], sys.argv[2], sys.argv[3]
for size in (128, 256):
    pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(svg, size, size, True)
    pb.savev(f"{root}/usr/share/icons/hicolor/{size}x{size}/apps/{pkg}.png",
             "png", [], [])
PY
then
    echo "  icons: scalable SVG + 128/256 PNG"
else
    echo "  icons: scalable SVG only (gdk-pixbuf unavailable)"
    rmdir "$root/usr/share/icons/hicolor/128x128/apps" \
          "$root/usr/share/icons/hicolor/128x128" \
          "$root/usr/share/icons/hicolor/256x256/apps" \
          "$root/usr/share/icons/hicolor/256x256" 2>/dev/null || true
fi

# ---- documentation ------------------------------------------------------
install -m644 "$src/README.md"         "$root/usr/share/doc/$pkg/README.md"
install -m644 "$here/copyright"        "$root/usr/share/doc/$pkg/copyright"
gzip -9 -n -c "$here/changelog"        > "$root/usr/share/doc/$pkg/changelog.Debian.gz"
gzip -9 -n -c "$here/parrot-janitor.1" > "$root/usr/share/man/man1/$pkg.1.gz"

# ---- control ------------------------------------------------------------
installed_size="$(du -sk "$root/usr" | cut -f1)"
sed -e "s/@VER@/${version}-${revision}/" \
    -e "s/@ARCH@/${arch}/" \
    -e "/^Section:/i Installed-Size: ${installed_size}" \
    "$here/control.in" > "$root/DEBIAN/control"

install -m755 "$here/postinst" "$root/DEBIAN/postinst"
install -m755 "$here/postrm"   "$root/DEBIAN/postrm"

# ---- normalise permissions ---------------------------------------------
# dpkg-deb records whatever mode is on disk, and this project's 0660 umask
# leaks into the PNGs gdk-pixbuf writes. Everything becomes 0755/0644 except
# the three executables (the /usr/bin entry is a symlink — its mode is
# ignored by dpkg).
find "$root" -type d -exec chmod 755 {} +
find "$root" -type f -exec chmod 644 {} +
chmod 755 "$root/usr/lib/$pkg/parrotjanitor.py" \
          "$root/DEBIAN/postinst" \
          "$root/DEBIAN/postrm"

# ---- build --------------------------------------------------------------
mkdir -p "$outdir"
fakeroot dpkg-deb --build --root-owner-group -Zxz "$root" "$outfile" >/dev/null

echo
echo "built: $outfile"
for field in Package Version Architecture Installed-Size Depends; do
    printf '  %-15s %s\n' "$field:" "$(dpkg-deb --field "$outfile" "$field")"
done
echo
echo "contents:"
dpkg-deb --contents "$outfile" | sed 's/^/  /'
echo

if command -v lintian >/dev/null 2>&1; then
    echo "---- lintian ----"
    lintian --tag-display-limit 0 "$outfile" 2>&1 | sed 's/^/  /' || true
    echo
fi

echo "install with:  sudo apt install ./${pkg}_${version}-${revision}_${arch}.deb"
echo "            or sudo dpkg -i ${pkg}_${version}-${revision}_${arch}.deb"
