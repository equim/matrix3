.PHONY: clean

all: matrix3_32.png matrix3_64.png

%_32.png: %.svg
	magick -size 32x32 $^ png:$@

%_64.png: %.svg
	magick -size 64x64 $^ png:$@

clean:
	rm -f *.png
