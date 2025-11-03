set dotenv-load

import "colors.just"

DATABASE_URL := "postgresql://$DATABASE_USER:$DATABASE_PASSWORD@$DATABASE_HOST:$DATABASE_PORT/$DATABASE_NAME?x-multi-statement=true&sslmode=disable"
MIGRATION_PATH := "./migrations/postgresql/"

# list all available commands of just
[private]
@default:
    just --list --unsorted

# generate go files with grpc
generate-proto:
    find ./api/grpc -name "*.proto" -type f | xargs protoc --proto_path=. \
        --go_out=. \
        --go-grpc_out=. \
        --go_opt=paths=source_relative \
        --go-grpc_opt=paths=source_relative 

# migrate database up
@migrate-up N="":
    echo -e "[{{CYAN}}INFO{{RESET}}] Starts migrate up database" 
    migrate -verbose -path "{{MIGRATION_PATH}}" -database "{{DATABASE_URL}}" up {{N}}
    echo -e "[{{GREEN}}SUCCESS{{RESET}}] Migration up was successful" 

# create new migration
@migrate-create MIGRATION_NAME:
    echo -e "[{{CYAN}}INFO{{RESET}}] Starts creating new migration" 
    migrate create -ext sql -dir "{{MIGRATION_PATH}}" {{MIGRATION_NAME}}
    echo -e "[{{GREEN}}SUCCESS{{RESET}}] Creating migrtaion was successful" 

# force database version
@migrate-force VERSION:
    echo -e "[{{CYAN}}INFO{{RESET}}] Starts forcing migration" 
    migrate -verbose -path "{{MIGRATION_PATH}}" -database "{{DATABASE_URL}}" force {{VERSION}}
    echo -e "[{{GREEN}}SUCCESS{{RESET}}] Forcing migration was successful" 

# fix latest dirty migration 
@migrate-fix:
    echo -e "[{{CYAN}}INFO{{RESET}}] Starts fixing latest dirty migration" && \
    VERSION_OUTPUT=$(migrate -path "{{MIGRATION_PATH}}" -database "{{DATABASE_URL}}" version 2>&1) && \
    if [[ "$VERSION_OUTPUT" == *"(dirty)"* ]]; then \
        VERSION=$(echo "$VERSION_OUTPUT" | cut -d ' ' -f 1) && \
        just migrate-force $VERSION && \
        just migrate-down 1 && \
        echo -e "[{{GREEN}}SUCCESS{{RESET}}] Fixing latest migration was successful" && \
    else \
        echo -e "[{{GREEN}}SUCCESS{{RESET}}] Your database is already clear" && \
    fi 

# migrate database down
@migrate-down N="-all":
    echo -e "[{{CYAN}}INFO{{RESET}}] Starts migrate down database" 
    migrate -verbose -path "{{MIGRATION_PATH}}" -database "{{DATABASE_URL}}" down {{N}}
    echo -e "[{{GREEN}}SUCCESS{{RESET}}] Migration down was successful"
