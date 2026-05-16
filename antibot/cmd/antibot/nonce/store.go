package nonce

import (
	"sync"
	"time"
)

// Entry хранит информацию о nonce для валидации токена.
type Entry struct {
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Store управляет хранением и валидацией nonce.
type Store struct {
	mu    sync.RWMutex // RWMutex позволяет параллельные чтения
	ttl   time.Duration
	items map[string]Entry // nonce -> entry с временем создания и истечения
}

// NewStore создаёт новый nonce store.
func NewStore(ttl time.Duration) *Store {
	return &Store{
		ttl:   ttl,
		items: make(map[string]Entry),
	}
}

// Put добавляет nonce в хранилище
// Оптимизация: убран cleanup из hot path для улучшения производительности
// Cleanup выполняется периодически в фоновой горутине.
func (s *Store) Put(nonce string) {
	// Кладём одноразовый ключ с дедлайном
	s.mu.Lock()
	defer s.mu.Unlock()
	// Убрали cleanupExpiredLocked() - это было узкое место!
	// Cleanup теперь выполняется только периодически через CleanupExpired()
	now := time.Now()
	s.items[nonce] = Entry{
		ExpiresAt: now.Add(s.ttl),
		CreatedAt: now,
	}
}

// Consume проверяет и удаляет nonce (одноразовое использование)
// Оптимизация: убран cleanup из hot path.
func (s *Store) Consume(nonce string) bool {
	// Однократное потребление nonce: проверка срока и удаление
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.items[nonce]
	if !ok {
		return false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(s.items, nonce)
		return false
	}
	delete(s.items, nonce)
	// Убрали cleanupExpiredLocked() - это было узкое место!
	return true
}

// IsValid проверяет, что nonce существует и не истёк (без удаления)
// Используется для проверки токена перед consume
// Оптимизация: использует RLock для параллельных чтений.
func (s *Store) IsValid(nonce string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.items[nonce]
	if !ok {
		return false
	}
	return time.Now().Before(entry.ExpiresAt)
}

// ConsumeIfValid атомарно проверяет и удаляет nonce (защита от race condition)
// Возвращает true если nonce был валиден и удалён, false в противном случае
// Оптимизация: убран cleanup из hot path.
func (s *Store) ConsumeIfValid(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.items[nonce]
	if !ok {
		return false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(s.items, nonce)
		return false
	}
	// Nonce валиден - удаляем его (одноразовое использование)
	delete(s.items, nonce)
	// Убрали cleanupExpiredLocked() - это было узкое место!
	return true
}

func (s *Store) cleanupExpiredLocked() {
	now := time.Now()
	for n, entry := range s.items {
		if now.After(entry.ExpiresAt) {
			delete(s.items, n)
		}
	}
}

// CleanupExpired удаляет все истекшие nonce из хранилища
// Публичный метод для периодической очистки в фоне.
func (s *Store) CleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked()
}
