deps:
	go get -u github.com/gorilla/mux
	go get -u github.com/rs/zerolog
	go get -u github.com/okta/okta-jwt-verifier-golang
	go get -u github.com/mattn/go-sqlite3

build: deps
	go build -o wg2fa

buildlinux: deps
	env GOOS=linux GOARCH=amd64 go build -o wg2fa

run: deps
	go run main.go

runlocal: deps
	go run main.go -- -aperture -debug