# DDoS-защита — шаблоны конфигов

Иллюстративные шаблоны конфигурации для DDoS-слоя. Основной конкретный конфиг здесь —
**connection/protocol-level** (nginx-директивы: таймауты, зона `limit_conn`, keepalive,
HTTP/2). L7 rate-based конфигурируется средствами каскада (rate-limit/challenge/policy,
см. [vision.md](vision.md)); волюметрика L3/L4 — вне периметра прокси. Контракт
поведения — [ddos-spec.md](ddos-spec.md).

**Сопутствующие материалы:** [ddos-rules-reference.md](ddos-rules-reference.md),
[ddos-entities-reference.md](ddos-entities-reference.md).

**Формат.** Иллюстративные фрагменты nginx-конфига (`http`/`server`) и YAML для
policy-ручки. Главное — структура и семантика, не точные значения: cap/таймауты —
системные константы пула, не клиентская настройка.

**Важно.** Это **не** конфиг стадии каскада. Директивы ниже живут до фазы решения
каскада: они рвут/ограничивают соединение раньше, чем запрос дойдет до анализа. Слой
наблюдения (Lua, log-фаза) только фиксирует итог дропа. Менять директивы per-request
из Lua нельзя — отсюда грубый (coarse) характер policy-ручки.

---

## Иерархия конфигов

```
http { … }                       ← глобальные таймауты + объявление зоны limit_conn + keepalive
server { … }                     ← применение limit_conn, listen http2 on, http2_max_concurrent_streams
build / Dockerfile               ← фиксация версии OpenResty/nginx ≥ 1.25.3 (Rapid Reset guard)
log-фаза (наблюдение)            ← $status/$request_time → тег slow_client/conn_flood
map $… → policy-ручка            ← опц., выбор жесткой зоны limit_conn под attack_mode (per-host)
policy[host].attack_mode/strictness ← per-host knob из backend (не локальный файл)
```

---

## 1. Slow-attacks: таймауты

Самый дешевый слой: чистый nginx, 0 Lua. Срезает дефолтные 60s до 10–15s, чтобы рвать
соединения, не завершающие заголовки/тело/чтение. Полностью обратимо.

```nginx
# http { } — глобальные таймауты приема/отдачи

# Slowloris: клиент не дослал строку запроса + заголовки в окно → 408
client_header_timeout   15s;     # дефолт 60s — срезаем

# Slow POST: клиент медленно/никогда не завершает тело → 408
client_body_timeout     15s;

# Slow read: клиент медленно вычитывает ответ → обрыв соединения
send_timeout            15s;

# Осознанные буферы под заголовки (защита от header-abuse)
large_client_header_buffers 4 8k;
```

> **Гарантия для легитимных клиентов.** Типовой запрос — единицы КБ; нормальный трафик
> укладывается в 15s с запасом. Срез бьет только по slow-attacks.
> `client_max_body_size` задается осознанно на прокси-путях.

---

## 2. Slow-attacks: зона `limit_conn` + keepalive

Cap одновременных соединений на один IP и ограничение удержания idle-keepalive-слотов.

```nginx
# http { } — объявление зоны и код отказа

# Зона считает одновременные соединения по IP (binary-форма компактнее в shared memory)
limit_conn_zone $binary_remote_addr zone=perip_conn:10m;

# Код отказа при превышении cap — целевой 503
limit_conn_status 503;

# Ограничить удержание idle-keepalive-слотов
keepalive_requests 1000;         # сколько запросов на одно соединение
keepalive_timeout  30s;          # время простоя до закрытия
```

```nginx
# server { } / location { } — применение cap

limit_conn perip_conn 20;        # cap одновременных соединений на IP (системная константа)
```

> **Семантика.** Превышение cap → nginx отказывает новому соединению кодом из
> `limit_conn_status` (503). В log-фазе это видно как `$status=503` и порождает тег
> `conn_flood`. Cap — системная константа пула, клиент в дашборде его не настраивает.

---

## 3. HTTP/2 DoS: билд + директивы

В основном свойство пропатченного билда + пара директив. Самостоятельный слой, не
зависит от slow-таймаутов.

```dockerfile
# Dockerfile / build — зафиксировать версию с Rapid Reset guard
# OpenResty/nginx >= 1.25.3 считает сброшенные-без-завершения HTTP/2-стримы
# и рвет соединение при превышении (CVE-2023-44487 и родня).
FROM openresty/openresty:1.25.3.1-alpine   # пример: версия >= 1.25.3
```

```nginx
# server { } — HTTP/2-настройки

listen 443 ssl;
http2 on;

# Лимит одновременных стримов в соединении (дефолт 128) — затюнить под профиль трафика
http2_max_concurrent_streams 128;

# keepalive_requests учитывается и для h2-мультиплекса
keepalive_requests 1000;

# Пороги CONTINUATION/PING/SETTINGS flood — задаются версией билда (см. changelog версии),
# отдельной директивой в конфиге могут не выражаться — это build-гарантия.
```

> Это HTTP/2 **DoS-mitigation**, а не HTTP/2 **fingerprint** (идентификация клиента).
> Frame-уровень не доходит до HTTP-семантики; каскад его не видит вовсе. Идентификация
> по h2-отпечатку — отдельный сигнал детектора, опционально дает h2-abuse для репутации.

---

## 4. Наблюдение в log-фазе

Не конфиг митигации — Lua-хук, превращающий nginx-дроп в наблюдаемое лог-событие.
Переиспользует тот же лог-контракт, что стадии каскада. Иллюстративно:

```nginx
# server { } / location { } — наблюдательный хук в log-фазе
log_by_lua_block {
    local status = tonumber(ngx.var.status)

    -- 408 ← таймаут заголовков/тела (client_header_timeout/client_body_timeout);
    -- 503 ← отказ limit_conn. Slow read (send_timeout) обрывает соединение БЕЗ 408,
    -- сюда не попадает (см. ограничение наблюдаемости ниже).
    if status == 408 or status == 503 then
        local bac_log = require "bac_log"
        -- access-фаза для slow-attacks не отрабатывает → ctx пуст, инициализируем
        if not ngx.ctx.bac then bac_log.init() end

        if status == 408 then
            bac_log.add_tag("slow_client")
            metrics.incr_by_ip_and_subnet("slow_client")   -- счетчик по IP / /24
        else
            bac_log.add_tag("conn_flood")
            metrics.incr_by_ip_and_subnet("conn_flood")
        end
        bac_log.emit()   -- emit() без аргументов: сериализует накопленный ctx
    end
}
```

> **Ограничение наблюдаемости.** Видно только то, что nginx отдает в log-фазе
> (`$status`, длительность `$request_time` → пишется в лог как `latency_ms`).
> Сам процесс цежения медленного соединения в реальном времени Lua не видит. **Slow
> read** (`send_timeout`) обрывает соединение **без 408** — наблюдается лишь как
> connection-close (обрыв, не тег `slow_client`). Счетчики по IP / /24 питают общий
> сток репутации и через него edge-ACL feed.

---

## 5. Policy-ручка: ужесточение под `attack_mode` (опционально)

Под `policy[host].attack_mode=on` / повышенной строгостью — более жесткая зона
`limit_conn` и/или ниже таймауты.

> **Честное ограничение.** nginx-директивы нельзя менять per-request из Lua.
> Реализация — `map`-driven выбор зоны per-host или грубый global-toggle, не плавная
> per-request подстройка. Этот слой может вовсе не делаться, если таймауты +
> наблюдение уже закрывают риск.

```nginx
# http { } — две зоны разной жесткости + map-выбор по host

limit_conn_zone $binary_remote_addr zone=perip_normal:10m;
limit_conn_zone $binary_remote_addr zone=perip_strict:10m;

# attack_mode проецируется в переменную (источник — policy[host] из backend)
map $host $conn_zone_for_host {
    default                     perip_normal;
    "under-attack.example.com"  perip_strict;   # иллюстративно; в реале — из policy-merge
}
```

```yaml
# per-host knob — НЕ локальный файл, приходит из backend как часть policy[host].
# Тот же merge attack_mode/strictness, что у каскада; здесь читается на выбор зоны/таймаутов.
example.com:
  attack_mode: false        # true → выбрать perip_strict + меньшие таймауты
  strictness: standard      # повышение → может ужесточать зону аналогично
```

> Связка `attack_mode`/`strictness` → выбор зоны — coarse: переключение per-host (через
> `map`) или глобально, не per-request. Значения cap/таймаутов для жесткой зоны —
> системные константы, как и в базовом слое.

---

## Соглашения по раскатке

1. **Таймауты — первыми и обратимо.** Дешевый слой; раскатывать с запасом: убедиться по
   логам (`$request_time` легитимных запросов), что нормальный трафик укладывается, —
   иначе ложные `408`.
2. **`limit_conn` cap калибровать по реальному профилю.** Слишком низкий cap бьет по
   NAT/корпоративным выходам (много легит-клиентов за одним IP). Стартовать
   консервативно, следить за тегом `conn_flood` на легит-трафике.
3. **HTTP/2-аудит самостоятелен.** Фиксация версии билда ≥ 1.25.3 и тюнинг
   `http2_max_concurrent_streams` не зависят от slow-слоев; делать параллельно.
4. **Policy-ручка опциональна и coarse** — не per-request adaptive (nginx так не умеет).
5. **Волюметрика L3/L4 — вне этих конфигов.** Митигируется ниже периметра прокси;
   максимум слоя — поставка нарушителей в edge-ACL feed.
