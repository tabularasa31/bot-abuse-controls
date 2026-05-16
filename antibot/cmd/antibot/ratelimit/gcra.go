package ratelimit

import (
	"sync"
	"time"
)

// GCRALimiter реализует Generic Cell Rate Algorithm (leaky bucket)
// Эффективный алгоритм rate limiting, основанный на идее "протекающего ведра"
// Запросы добавляются в ведро, которое протекает с постоянной скоростью.
type GCRALimiter struct {
	mu           sync.Mutex
	buckets      map[string]*bucket // IP -> bucket
	emissionRate time.Duration      // Интервал между разрешёнными запросами (протечка)
	burstSize    int                // Максимальный размер "всплеска" (размер ведра)
}

// bucket представляет "ведро" для одного IP.
type bucket struct {
	lastRequest time.Time // Время последнего запроса
	allowance   float64   // Текущий "баланс" ведра (сколько запросов можно сделать)
}

// NewGCRALimiter создаёт новый GCRA limiter
// maxRequests - максимальное количество запросов
// window - временное окно
// Например: 10 запросов в минуту = emissionRate = 6 секунд, burstSize = 10.
func NewGCRALimiter(maxRequests int, window time.Duration) *GCRALimiter {
	// emissionRate - интервал между разрешёнными запросами
	emissionRate := window / time.Duration(maxRequests)

	return &GCRALimiter{
		buckets:      make(map[string]*bucket),
		emissionRate: emissionRate,
		burstSize:    maxRequests,
	}
}

// Allow проверяет, разрешён ли запрос с данного IP
// Возвращает true если запрос разрешён, false если превышен лимит.
func (g *GCRALimiter) Allow(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()

	// Получаем или создаём bucket для IP
	b, exists := g.buckets[ip]
	if !exists {
		// Новый IP - создаём bucket с полным allowance
		b = &bucket{
			lastRequest: now,
			allowance:   float64(g.burstSize),
		}
		g.buckets[ip] = b
		return true
	}

	// Вычисляем, сколько времени прошло с последнего запроса
	elapsed := now.Sub(b.lastRequest)

	// Ведро "протекает" - увеличиваем allowance пропорционально времени
	// allowance увеличивается на elapsed / emissionRate
	// Например, если emissionRate = 6 секунд, и прошло 12 секунд,
	// то allowance увеличится на 2
	b.allowance += float64(elapsed) / float64(g.emissionRate)

	// Ограничиваем allowance максимальным размером burst
	if b.allowance > float64(g.burstSize) {
		b.allowance = float64(g.burstSize)
	}

	// Проверяем, достаточно ли allowance для запроса
	if b.allowance >= 1.0 {
		// Разрешён запрос - уменьшаем allowance на 1
		b.allowance -= 1.0
		b.lastRequest = now
		return true
	}

	// Недостаточно allowance - запрос заблокирован
	// Обновляем lastRequest для корректного расчёта в следующий раз
	b.lastRequest = now
	return false
}

// Cleanup удаляет неактивные buckets для экономии памяти
// Использует window из конфигурации (хранится как burstSize * emissionRate).
func (g *GCRALimiter) Cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	// Удаляем buckets, которые не использовались дольше чем 2 окна
	// window = burstSize * emissionRate
	window := time.Duration(g.burstSize) * g.emissionRate
	cutoff := now.Add(-window * 2)

	for ip, b := range g.buckets {
		if b.lastRequest.Before(cutoff) {
			delete(g.buckets, ip)
		}
	}
}
