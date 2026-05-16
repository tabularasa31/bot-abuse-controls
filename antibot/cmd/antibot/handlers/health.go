package handlers

import (
	"encoding/json"
	"net/http"
)

// HealthHandler возвращает статус здоровья сервиса
// Используется для мониторинга и проверки работоспособности.
func (s *Server) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.withTimeout(r)
	defer cancel()

	logger := s.getLoggerWithContext(r)

	// Проверяем контекст
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled in health check", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	if logger != nil {
		logger.Debug("Health check requested")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "antibot",
	})
}
