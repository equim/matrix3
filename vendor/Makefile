# Update third party javascript dependencies

.PHONY: all update clean

all: tldts.js

update: clean all

# This library is used to extract domains and suffixes from hostnames.
tldts.js: SRCURL="https://unpkg.com/tldts@7/dist/index.esm.min.js"

%.js:
	wget -O $@ $(SRCURL)

clean:
	rm -f *.js
