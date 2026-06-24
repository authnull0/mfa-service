package session

import (
	"log"
	"os"
	"strconv"

	"github.com/go-redis/redis"
)

// Redis is the shared Redis client used across the service.
// Initialised once at startup via InitRedis().
// nil when Redis is unavailable — callers must check before use.
var Redis *redis.Client

// InitRedis connects to Redis using env vars and verifies the connection.
// If the connection fails, Redis is left nil and challenge persistence falls
// back to the in-memory store (challenges are lost on restart but the service
// stays up).
func InitRedis() {
	host := envOr("REDIS_HOST", "localhost")
	port := envOr("REDIS_PORT", "6379")
	password := envOr("REDIS_PASSWORD", "")
	db, _ := strconv.Atoi(envOr("REDIS_DB", "0"))

	client := redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: password,
		DB:       db,
	})

	if _, err := client.Ping().Result(); err != nil {
		log.Printf("[redis] connection failed (%v) — challenge store will use in-memory fallback", err)
		return
	}

	Redis = client
	log.Printf("[redis] connected: %s:%s db=%d", host, port, db)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
