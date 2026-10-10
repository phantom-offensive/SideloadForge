.PHONY: build build-windows build-linux clean

APP := forge

build:
	go build -o $(APP) ./cmd/forge/

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o build/$(APP)_windows_amd64.exe ./cmd/forge/

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o build/$(APP)_linux_amd64 ./cmd/forge/

clean:
	rm -f $(APP)
	rm -rf build/
