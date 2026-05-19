# Generate resources required by the Chrome Web Store

all: marquee-tile.png small-tile.png

marquee-tile.png: SIZE=1400x560
small-tile.png: SIZE=440x280

%.png: %.svg
	magick -size $(SIZE) $^ png:$@

clean:
	rm -f *.png
