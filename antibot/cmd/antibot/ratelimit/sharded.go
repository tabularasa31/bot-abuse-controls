package ratelimit

import (
	"hash/fnv"
	"time"
)

// ShardedLimiter обёртка для sharding rate limiter
// Разделяет нагрузку на несколько shards для снижения contention блокировок.
type ShardedLimiter struct {
	shards     []*GCRALimiter
	shardCount int
}

// NewShardedGCRALimiter создаёт sharded GCRA limiter
// shardCount - количество shards (рекомендуется количество CPU ядер).
func NewShardedGCRALimiter(maxRequests int, window time.Duration, shardCount int) *ShardedLimiter {
	if shardCount <= 0 {
		shardCount = 1
	}

	shards := make([]*GCRALimiter, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = NewGCRALimiter(maxRequests, window)
	}

	return &ShardedLimiter{
		shards:     shards,
		shardCount: shardCount,
	}
}

// getShard возвращает shard для данного IP на основе хеша.
func (sl *ShardedLimiter) getShard(ip string) *GCRALimiter {
	hash := fnv.New32a()
	hash.Write([]byte(ip))
	shardIndex := int(hash.Sum32()) % sl.shardCount
	return sl.shards[shardIndex]
}

// Allow проверяет, разрешён ли запрос с данного IP.
func (sl *ShardedLimiter) Allow(ip string) bool {
	return sl.getShard(ip).Allow(ip)
}

// Cleanup очищает все shards.
func (sl *ShardedLimiter) Cleanup() {
	for _, shard := range sl.shards {
		shard.Cleanup()
	}
}
