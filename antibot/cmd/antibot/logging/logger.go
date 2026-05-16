package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Logger асинхронно логирует события для ML модели.
type Logger struct {
	writer      Writer
	buffer      *Buffer
	flushTicker *time.Ticker
	done        chan struct{}
	wg          sync.WaitGroup
	enabled     bool
	sampleRate  float64
	mu          sync.Mutex
}

// Config конфигурация логгера.
type Config struct {
	Enabled       bool
	LogPath       string
	BufferSize    int
	FlushInterval time.Duration
	SampleRate    float64 // 0.0 - 1.0, вероятность логирования каждого события
}

// NewLogger создаёт новый логгер.
func NewLogger(config Config) (*Logger, error) {
	if !config.Enabled {
		return &Logger{enabled: false}, nil
	}

	writer, err := NewJSONLWriter(config.LogPath)
	if err != nil {
		return nil, err
	}

	buffer := NewBuffer(config.BufferSize)
	flushTicker := time.NewTicker(config.FlushInterval)

	l := &Logger{
		writer:      writer,
		buffer:      buffer,
		flushTicker: flushTicker,
		done:        make(chan struct{}),
		enabled:     true,
		sampleRate:  config.SampleRate,
	}

	// Запускаем фоновую горутину для периодического сброса буфера
	l.wg.Add(1)
	go l.flushLoop()

	return l, nil
}

// Log логирует событие (асинхронно).
func (l *Logger) Log(event *Event) {
	if !l.enabled {
		return
	}

	// Sampling: пропускаем события с вероятностью (1 - sampleRate)
	//nolint:gosec // log sampling does not need crypto-grade randomness
	if l.sampleRate < 1.0 && rand.Float64() > l.sampleRate {
		return
	}

	// Генерируем request_id если не указан
	if event.RequestID == "" {
		event.RequestID = uuid.New().String()
	}

	// Добавляем в буфер (не блокирует)
	l.buffer.Add(event)
}

// flushLoop периодически сбрасывает буфер.
func (l *Logger) flushLoop() {
	defer l.wg.Done()

	for {
		select {
		case <-l.done:
			// Финальный сброс перед закрытием
			l.flush()
			return
		case <-l.flushTicker.C:
			l.flush()
		case <-l.buffer.FlushChan():
			// Сброс при заполнении буфера
			l.flush()
		}
	}
}

// flush сбрасывает буфер в writer.
func (l *Logger) flush() {
	events := l.buffer.Flush()
	if len(events) == 0 {
		return
	}

	for _, event := range events {
		if err := l.writer.Write(event); err != nil {
			log.Printf("Failed to write ML log event: %v", err)
		}
	}
}

// Close закрывает логгер и сбрасывает оставшиеся события.
func (l *Logger) Close() error {
	if !l.enabled {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	close(l.done)
	l.flushTicker.Stop()
	l.buffer.Close()
	l.wg.Wait()

	// Финальный сброс
	l.flush()

	return l.writer.Close()
}

// HashIP хеширует IP адрес для приватности.
func HashIP(ip string) string {
	hash := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(hash[:])
}
