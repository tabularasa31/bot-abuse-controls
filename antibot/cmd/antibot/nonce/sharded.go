package nonce

import (
	"hash/fnv"
	"sync"
	"time"
)

// StoreInterface определяет интерфейс для nonce store
// Позволяет использовать как обычный Store, так и ShardedStore.
type StoreInterface interface {
	Put(nonce string)
	Consume(nonce string) bool
	IsValid(nonce string) bool
	ConsumeIfValid(nonce string) bool
	CleanupExpired()
}

// ShardedStore управляет хранением nonce с sharding для снижения contention
// Разделяет nonce на несколько shards для параллельной обработки.
type ShardedStore struct {
	shards     []*Store
	shardCount int
}

// NewShardedStore создаёт sharded nonce store
// shardCount - количество shards (рекомендуется количество CPU ядер).
func NewShardedStore(ttl time.Duration, shardCount int) *ShardedStore {
	if shardCount <= 0 {
		shardCount = 1
	}

	shards := make([]*Store, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = NewStore(ttl)
	}

	return &ShardedStore{
		shards:     shards,
		shardCount: shardCount,
	}
}

// getShard возвращает shard для данного nonce на основе хеша.
func (ss *ShardedStore) getShard(nonce string) *Store {
	hash := fnv.New32a()
	hash.Write([]byte(nonce))
	shardIndex := int(hash.Sum32()) % ss.shardCount
	return ss.shards[shardIndex]
}

// Put добавляет nonce в хранилище.
func (ss *ShardedStore) Put(nonce string) {
	ss.getShard(nonce).Put(nonce)
}

// Consume проверяет и удаляет nonce (одноразовое использование).
func (ss *ShardedStore) Consume(nonce string) bool {
	return ss.getShard(nonce).Consume(nonce)
}

// IsValid проверяет, что nonce существует и не истёк (без удаления).
func (ss *ShardedStore) IsValid(nonce string) bool {
	return ss.getShard(nonce).IsValid(nonce)
}

// ConsumeIfValid атомарно проверяет и удаляет nonce.
func (ss *ShardedStore) ConsumeIfValid(nonce string) bool {
	return ss.getShard(nonce).ConsumeIfValid(nonce)
}

// CleanupExpired удаляет все истекшие nonce из всех shards.
func (ss *ShardedStore) CleanupExpired() {
	// Запускаем cleanup параллельно для всех shards
	var wg sync.WaitGroup
	for _, shard := range ss.shards {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			s.CleanupExpired()
		}(shard)
	}
	wg.Wait()
}
