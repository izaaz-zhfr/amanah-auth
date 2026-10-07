run:     ; go run ./cmd/api
test:    ; go test ./... -count=1 -race
test-pg: ; TEST_DATABASE_URL='postgres://USER:PASS@localhost:5432/amanah?sslmode=disable' go test ./... -count=1 -p 1
