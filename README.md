# QueueDroid Server

QueueDroid Server is a backend service for managing SMS message queues.

---

## Table of Contents

- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running](#running)

---

## Requirements

- **Go** 1.20+
- **Git**
- **Database**: SQLite (default), [PostgreSQL](https://www.postgresql.org/download/), or [MySQL](https://dev.mysql.com/downloads/)
- **Broker**: [RabbitMQ](https://www.rabbitmq.com/download.html) (required)

---

## Quick Start

```sh
git clone https://github.com/queuedroid/qdroid-server.git
cd qdroid-server
go mod download
cp .env.example .env
go run server.go
```

> [!TIP]
>
> On your first run, use the `--migrate-db` flag to set up the database schema:
>
> ```bash
> go run server.go --migrate-db
> ```

---

## Configuration

Edit `.env` for your setup. Key variables:

- `PORT` - Server port (default: 8080)
- `DB_DIALECT` - `sqlite`, `postgres`, or `mysql`
- `DB_PATH` - SQLite file (default: `qdroid.db`)
- `POSTGRES_DSN` / `MYSQL_DSN` - DSN for Postgres/MySQL
- `CORS_ORIGINS` - Allowed origins
- `RABBITMQ_API_URL` - RabbitMQ management API URL (default: `http://localhost:15672`)
- `RABBITMQ_USERNAME` / `RABBITMQ_PASSWORD` - RabbitMQ management credentials

---

## Running

```sh
go run server.go
```

**Flags:**

- `--debug` : Enable debug logs
- `--migrate-db` : Run DB migrations

Example:

```sh
go run server.go --debug --migrate-db
```

---

## License

This project is licensed under the GNU GPL v3. See [LICENSE](LICENSE) for details.
