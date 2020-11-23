build:
	rm -rf ui/dist dist
	cd ui && yarn build && mv dist .. && cd ..
	rice embed-go
	go build --ldflags="-s -w"
	./darwinmeta
