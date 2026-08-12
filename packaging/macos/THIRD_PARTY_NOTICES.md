# Third-party runtime notices

The macOS release bundle contains only non-system dynamic libraries reached
from Guard's GTK/libadwaita executable and its bundled image-loader modules.
Exact filenames are verified from `Contents/Frameworks` at build time.

Principal upstream components and licenses:

| Component | License family | Upstream |
|---|---|---|
| GTK, GLib, GdkPixbuf, Pango, libadwaita | LGPL-2.1-or-later | https://www.gtk.org/ |
| Cairo | LGPL-2.1-or-later / MPL-1.1 | https://www.cairographics.org/ |
| librsvg | LGPL-2.1-or-later | https://gitlab.gnome.org/GNOME/librsvg |
| HarfBuzz | MIT | https://harfbuzz.github.io/ |
| Graphene | MIT | https://github.com/ebassi/graphene |
| Graphite2 | MPL-2.0 / LGPL-2.1-or-later / GPL-2.0-or-later | https://graphite.sil.org/ |
| libepoxy | MIT | https://github.com/anholt/libepoxy |
| FriBidi | LGPL-2.1-or-later | https://github.com/fribidi/fribidi |
| gettext runtime (`libintl`) | LGPL-2.1-or-later | https://www.gnu.org/software/gettext/ |
| AppStream | LGPL-2.1-or-later | https://www.freedesktop.org/software/appstream/ |
| libxmlb | LGPL-2.1-or-later | https://github.com/hughsie/libxmlb |
| libfyaml | MIT | https://github.com/pantoniou/libfyaml |
| libthai, libdatrie | LGPL-2.1-or-later | https://linux.thai.net/projects/libthai |
| X11/Xrender/Xext, XCB, libXau, libXdmcp | MIT/X11 | https://www.x.org/ |
| Fontconfig | MIT | https://www.freedesktop.org/wiki/Software/fontconfig/ |
| FreeType | FreeType License / GPL-2.0-or-later | https://freetype.org/ |
| libpng | libpng-2.0 | http://www.libpng.org/pub/png/libpng.html |
| libjpeg-turbo | BSD-3-Clause / IJG / zlib | https://libjpeg-turbo.org/ |
| LibTIFF | libtiff | http://www.simplesystems.org/libtiff/ |
| Pixman | MIT | https://www.pixman.org/ |
| PCRE2 | BSD-3-Clause | https://www.pcre.org/ |
| LZO | GPL-2.0-or-later | https://www.oberhumer.com/opensource/lzo/ |
| XZ Utils (`liblzma`) | 0BSD | https://tukaani.org/xz/ |
| Zstandard | BSD-3-Clause | https://facebook.github.io/zstd/ |

These libraries remain replaceable shared objects in `Contents/Frameworks`;
Guard does not add technical restrictions that prevent a recipient from
relinking/replacing LGPL components for debugging and private modification.
Corresponding-source archives and full license texts for the exact release
versions must accompany the Alpha distribution or be offered from the release
download page. The packaging report records versions observed on the build
host. Apple system libraries are not redistributed.
