# 第三方运行时许可证说明

macOS 发布包只包含 Guard 的 GTK/libadwaita 运行时依赖和图像加载模块。确切文件名由构建脚本从 `Contents/Frameworks` 检查；Apple 系统库不随包重新分发。

| 组件 | 许可证族 | 官方地址 |
| --- | --- | --- |
| GTK、GLib、GdkPixbuf、Pango、libadwaita | LGPL-2.1 或更高版本 | https://www.gtk.org/ |
| Cairo | LGPL-2.1 或更高版本 / MPL-1.1 | https://www.cairographics.org/ |
| librsvg | LGPL-2.1 或更高版本 | https://gitlab.gnome.org/GNOME/librsvg |
| HarfBuzz、Graphene、libepoxy、Pixman | MIT | https://harfbuzz.github.io/ |
| Graphite2、FriBidi、libthai、libdatrie | 多许可证，见上游 | https://graphite.sil.org/ |
| gettext、AppStream、libxmlb | LGPL-2.1 或更高版本 | https://www.gnu.org/software/gettext/ |
| libfyaml | MIT | https://github.com/pantoniou/libfyaml |
| X11/Xrender/Xext、XCB、libXau、libXdmcp | MIT/X11 | https://www.x.org/ |
| Fontconfig | MIT | https://www.freedesktop.org/wiki/Software/fontconfig/ |
| FreeType | FreeType License / GPL-2.0 或更高版本 | https://freetype.org/ |
| libpng | libpng-2.0 | http://www.libpng.org/pub/png/libpng.html |
| libjpeg-turbo | BSD-3-Clause / IJG / zlib | https://libjpeg-turbo.org/ |
| LibTIFF | libtiff | http://www.simplesystems.org/libtiff/ |
| PCRE2 | BSD-3-Clause | https://www.pcre.org/ |
| LZO | GPL-2.0 或更高版本 | https://www.oberhumer.com/opensource/lzo/ |
| XZ Utils（liblzma） | 0BSD | https://tukaani.org/xz/ |
| Zstandard | BSD-3-Clause | https://facebook.github.io/zstd/ |

LGPL 组件保持可替换的动态库形式。发布时应同时提供对应版本的许可证全文和源码获取方式；本清单不构成新的许可证限制。
