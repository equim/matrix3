VERSION = 0.01
.PHONY: clean

all: matrix3_32.png matrix3_64.png matrix3_128.png

dist: matrix3-$(VERSION).zip

%.zip: all
	git ls-files --exclude-standard | zip $@ -@ -x "tools/*" ".gitignore" "*/.gitignore" "Makefile" "*/Makefile"

%_32.png: %.svg
	magick -size 32x32 $^ png:$@

%_64.png: %.svg
	magick -size 64x64 $^ png:$@

%_128.png: %.svg
	magick -size 128x128 $^ png:$@

clean:
	rm -f *.png *.crx *.zip
