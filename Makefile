build: clean
	cd ui && yarn build && mv dist .. && cd ..
	rice embed-go
	go build --ldflags="-s -w"
clean:
	rm -rf ./ui/dist ./dist ./darwinmeta
run:
	./darwinmeta

