# QueueDroid Server

QueueDroid Server is a backend service for managing SMS message queues.

---

## Table of Contents

- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running](#running)
- [Reference](#reference)

---

## Requirements

- **Go** 1.20+
- **Git**
- **Make** (for running setup/build commands)
- **Database**: SQLite (default), [PostgreSQL](https://www.postgresql.org/download/), or [MySQL](https://dev.mysql.com/downloads/)
- **Broker**: [RabbitMQ](https://www.rabbitmq.com/download.html) (required)

---

## Quick Start

You can use the provided `Makefile` for setup and running the server.

```sh
git clone https://github.com/queuedroid/qdroid-server.git
cd qdroid-server
make setup
make dev
```

Or, if you prefer to run manually:

```sh
go mod download
cp .env.example .env
go run server.go --env-file .env --migrate-db
```

> [!TIP]
>
> On your first run, use the `--migrate-db` flag to set up the database schema:
>
> ```bash
> go run server.go --migrate-db
> ```
>
> You can also specify a custom environment file using the `--env-file` flag:
>
> ```bash
> go run server.go --env-file .env
> ```
>
> If no `--env-file` is provided, configuration values are read directly from the environment variables.

---

## Configuration

Edit `.env` for your setup. Key variables:

- `PORT` - Server port (default: 8080)
- `DB_DIALECT` - `sqlite`, `postgres`, or `mysql`
- `DB_PATH` - SQLite file (default: `qdroid.db`)
- `DB_USER` - Database username (Postgres/MySQL)
- `DB_PASSWORD` - Database password (Postgres/MySQL)
- `DB_HOST` - Database host (default: `localhost`)
- `DB_PORT` - Database port (default: `5432` for Postgres, `3306` for MySQL)
- `DB_NAME` - Database name
- `DB_SSLMODE` - (Postgres only, default: `disable`)
- `CORS_ORIGINS` - Allowed origins
- `RABBITMQ_API_URL` - RabbitMQ management API URL (default: `http://localhost:15672`)
- `RABBITMQ_USERNAME` / `RABBITMQ_PASSWORD` - RabbitMQ management credentials

---

## Running

You can use `make` targets for common tasks:

```sh
make dev      # Run in development mode (with debug and migration)
make run      # Run the server with .env
make build    # Build the server binary
make start    # Start the built binary
make docs     # Generate Swagger docs
```

Or run manually:

```sh
go run server.go
```

**Flags:**

- `--debug` : Enable debug logs
- `--migrate-db` : Run DB migrations
- `--env-file <file>` : Load environment variables from a custom file

Example:

```sh
go run server.go --debug --migrate-db --env-file .env.production
```

---

## Reference

### API Documentation

The OpenAPI (Swagger) documentation is served at the [`/docs/`](https://api.queuedroid.com/docs/index.html).

---

## License

This project is licensed under the GNU GPL v3. See [LICENSE](LICENSE) for details.
