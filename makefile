build:
	go build -o wg2fa

run:
	go run main.go

runlocaldebug: deps
	go run main.go -- -debug -dangerauth