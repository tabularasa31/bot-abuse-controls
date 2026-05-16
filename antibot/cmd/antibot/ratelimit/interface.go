package ratelimit

// LimiterInterface определяет интерфейс для rate limiting
// Позволяет легко переключаться между реализациями (GCRA, sharded GCRA).
type LimiterInterface interface {
	Allow(ip string) bool
	Cleanup()
}
