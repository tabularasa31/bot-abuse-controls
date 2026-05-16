package logging

import (
	"sync"
)

// Buffer буферизует события для асинхронной записи.
type Buffer struct {
	events    []*Event
	mu        sync.RWMutex // RWMutex позволяет параллельные чтения для Size()
	maxSize   int
	flushChan chan struct{}
	closed    bool
}

// NewBuffer создаёт новый буфер.
func NewBuffer(maxSize int) *Buffer {
	return &Buffer{
		events:    make([]*Event, 0, maxSize),
		maxSize:   maxSize,
		flushChan: make(chan struct{}, 1),
	}
}

// Add добавляет событие в буфер.
func (b *Buffer) Add(event *Event) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return false
	}

	b.events = append(b.events, event)

	// Если буфер заполнен, сигнализируем о необходимости сброса
	if len(b.events) >= b.maxSize {
		select {
		case b.flushChan <- struct{}{}:
		default:
		}
		return true
	}

	return true
}

// Flush возвращает все события из буфера и очищает его.
func (b *Buffer) Flush() []*Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events) == 0 {
		return nil
	}

	events := make([]*Event, len(b.events))
	copy(events, b.events)

	// Очищаем слайс, но сохраняем capacity для переиспользования
	b.events = b.events[:0]

	// Если capacity намного больше maxSize (например, после большого flush),
	// пересоздаём слайс с оптимальным размером для экономии памяти
	// Это предотвращает утечку памяти при частых flush операциях
	if cap(b.events) > b.maxSize*2 {
		b.events = make([]*Event, 0, b.maxSize)
	}

	return events
}

// Size возвращает текущий размер буфера
// Оптимизация: использует RLock для параллельных чтений.
func (b *Buffer) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.events)
}

// Close закрывает буфер.
func (b *Buffer) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	close(b.flushChan)
}

// FlushChan возвращает канал для сигналов о необходимости сброса.
func (b *Buffer) FlushChan() <-chan struct{} {
	return b.flushChan
}
