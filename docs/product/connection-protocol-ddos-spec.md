# Connection/Protocol-level DDoS — спецификация (slow-attacks + HTTP/2 DoS)

**Версия:** v0.1 · **Статус:** проектный контракт (целевое поведение) · **Дата:** 2026-05-31

Документ описывает целевое поведение для класса DDoS-атак уровня соединения и
протокола — как [vision.md](vision.md) описывает каскад: спецификация, по которой
строится реализация. Что из этого уже в стенде, а что ещё нет — сверяй с
[PROGRESS.md](../../PROGRESS.md) и кодом `infra/demo-stand/lua/`.

**Сопутствующие материалы (как у vision):**
[connproto-ddos-rules-reference.md](connproto-ddos-rules-reference.md) — правила/сигналы
в формате «если условие → действие»; [connproto-ddos-entities-reference.md](connproto-ddos-entities-reference.md)
— словарь сущностей (директивы, теги, поля лога, перечисления);
[connproto-ddos-config-templates.md](connproto-ddos-config-templates.md) — структура
nginx-директив и порогов.

---

## 1. Что это

Защита от DDoS-атак, которые не сводятся к частоте HTTP-запросов и потому
невидимы для rate-limit-слоя каскада (L4). Два семейства:

- **Slow-attacks** (slowloris / slow POST / slow read) — атака на уровне TCP-соединения:
  много соединений, которые медленно или никогда не завершают передачу, выедая слоты
  воркеров.
- **HTTP/2 DoS** (Rapid Reset CVE-2023-44487 и родня) — атака на уровне HTTP/2-фреймов:
  дешёвое для клиента создание+отмена стримов, дорогое для сервера.

Это третий слой DDoS-картины (см. roadmap §4): L7 rate-based уже закрыт D-серией
(D12–D17), волюметрика L3/L4 — вне нашего скоупа (reality-3). Этот документ — про
средний слой, который реально новый и наш.

## 2. Зачем (почему каскад этого не ловит)

Каскад (`verdict.lua`: hygiene→reputation→tls_fp→rate_limits→verification) исполняется
в фазе `access_by_lua` — после того, как nginx распарсил строку запроса и заголовки.
Атаки этого класса живут ниже этой точки:

| Атака | Почему мимо каскада |
|---|---|
| slowloris | заголовки не дослал → `access_by_lua` для соединения толком не запускается |
| slow POST/read | мало запросов, много idle-соединений → GCRA (`rate_limit.lua`) считает частоту, не соединения |
| Rapid Reset | стрим сброшен на frame-уровне до HTTP-семантики → `rate_limit`/`attack_mode` per-request его не видят |

Дополнительно: challenge (C-серия) против такого клиента бесполезен — он не
завершает запрос, страница challenge до него не доходит.

**Текущее состояние стенда — уязвим из коробки:** в `nginx.demo.conf` нет ни
`limit_conn`, ни кастомных `client_header_timeout`/`client_body_timeout`/`send_timeout`
(дефолт 60s на заголовки). `client_max_body_size` задан только на solver-локации
(`nginx.demo.conf:459`).

## 3. Архитектурный принцип: nginx митигирует → Lua наблюдает → reputation эскалирует

Ключевой инвариант: это НЕ новая стадия каскада. Slow-клиент и сброшенный стрим
не доходят до `access_by_lua`, поэтому добавлять стадию в `verdict.lua` некуда и незачем.
Паттерн для всего класса:

```
nginx/билд   →  МИТИГИРУЕТ (директивы, пропатченная версия)   ← реальная защита
   Lua       →  НАБЛЮДАЕТ (log_by_lua / metrics → bac_log)     ← наш BAC-слой
reputation   →  ЭСКАЛИРУЕТ (D14 подсеть/IP → D15 → edge-ACL)   ← общий сток DDoS
```

Наш BAC-вклад здесь — не блокировка (её делает nginx), а превращение nginx-дропов в
наблюдаемый, репутационно-питающий сигнал и его эскалация в общий DDoS-механизм.

## 4. Как — slow-attacks (D21–D23)

### 4.1 Baseline-директивы (D21) — реальная защита
Чистый nginx-конфиг, 0 Lua, даёт ~80% эффекта:

- `client_header_timeout` / `client_body_timeout` / `send_timeout` → срезать до 10–15s
  (рвёт соединения, не завершающие заголовки/тело/чтение).
- `limit_conn` зона по `$binary_remote_addr` — cap одновременных соединений на IP,
  `limit_conn_status` для кода отказа.
- `keepalive_requests` / `keepalive_timeout` — ограничить idle-keepalive.
- `large_client_header_buffers`, осознанный `client_max_body_size` для прокси-путей.

Гарантия: легитимные клиенты с запасом (solver шлёт <2KB; `client_body_buffer_size 8k`
уже стоит). Полностью обратимо.

### 4.2 Observability (D22) — наш слой
`log_by_lua`-хук читает `$status`/`$request_time`/`$connection_requests`; таймаут (408) и
отказ `limit_conn` (503) → событие `bac_log` с тегом `slow_client`/`conn_flood` → дашборд
+ счётчик по IP / /24. Переиспользует `bac_log`-контракт (как hygiene/reputation).
Ограничение: видно только то, что nginx отдаёт в log-фазе; сам процесс цежения не виден.

### 4.3 Policy-ручка (D23) — опционально
Под `attack_mode`/повышенной strictness — более жёсткая `limit_conn`-зона / ниже таймауты.
⚠️ **Честное ограничение:** nginx-директивы нельзя менять per-request из Lua. Реализация —
`map`-driven выбор зоны per-host или coarse global-toggle, не плавная per-request
подстройка. Может не делаться, если D21+D22 закрывают риск.

## 5. Как — HTTP/2 DoS (E3–E4)

### 5.1 Mitigation-аудит (E3) — в основном билд + директивы
- Подтвердить версию OpenResty/nginx ≥ 1.25.3 (считает сброшенные стримы, рвёт соединение
  при превышении reset-без-завершённого-запроса). Зафиксировать в Dockerfile/конфиге стенда.
- `http2_max_concurrent_streams` (дефолт 128) — затюнить; `keepalive_requests` для h2;
  пороги CONTINUATION/PING/SETTINGS flood по версии.
- `http2 on` уже стоит (`nginx.demo.conf:291`).

### 5.2 h2-abuse как сигнал репутации (E4) — опционально, зависит от E2
Если спайк E2 (HTTP/2 fingerprint) даст способ видеть аномальные SETTINGS/stream-паттерны
— использовать как сигнал в reputation/score, даже когда frame-митигация остаётся в nginx.
Детект-ассист, не митигация.

> ⚠️ **E3 ≠ E2.** E2 — это HTTP/2 fingerprint (детект/идентификация клиента,
> анти-JA4-ротация). E3 — HTTP/2 DoS-mitigation (Rapid Reset). Разные слои задачи.

## 6. Что переиспользуем
`bac_log` + теги, `metrics.lua`, D14 (subnet/IP reputation) как сток повторных нарушителей,
edge-ACL feed (roadmap §4.3) для эскалации в сетевой слой, policy strictness/`attack_mode`
merge для ручки.

## 7. Честные границы
- **Волюметрика L3/L4** (SYN/UDP/амплификация) — вне OpenResty (хендшейк уже состоялся).
  Reality-3, наш максимум — контракт edge-ACL feed (roadmap §4.3).
- **Adaptive per-request лимиты** — nginx так не умеет (см. §4.3).
- HTTP/2-DoS — слабый fit для Lua: фикс на 90% «пропатченный билд + 2 директивы», наш
  value-add = аудит (E3) + fp-as-signal (E4).

## 8. Состав и порядок внедрения
| Этап | Суть | Зависит от |
|---|---|---|
| Baseline-директивы | таймауты + `limit_conn` (slow) | — |
| Observability | nginx-дропы → `bac_log` + репутация | baseline |
| Policy-ручка | ужесточение под `attack_mode` (опц.) | observability |
| HTTP/2 mitigation-аудит | пропатченный билд + `http2_max_concurrent_streams` | — |
| h2-abuse как сигнал | репутационный сигнал по h2-fp (опц.) | HTTP/2 fingerprint-спайк |

Порядок: baseline (самый дешёвый и срочный — стенд уязвим из коробки) → observability →
policy-ручка; HTTP/2-аудит самостоятелен. Самодостаточный разбор правил и сигналов —
в [connproto-ddos-rules-reference.md](connproto-ddos-rules-reference.md).
