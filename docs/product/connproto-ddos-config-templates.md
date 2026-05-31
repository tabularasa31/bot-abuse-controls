# Connection/Protocol-level DDoS — шаблоны конфигов

Иллюстративные шаблоны nginx-директивной конфигурации для класса DDoS уровня
соединения и протокола (slow-attacks + HTTP/2 DoS): таймауты, зона `limit_conn`,
keepalive, HTTP/2-настройки, плюс per-host policy-ручка. Источник правды по поведению —
[connection-protocol-ddos-spec.md](connection-protocol-ddos-spec.md).

**Сопутствующие материалы:**
[connproto-ddos-rules-reference.md](connproto-ddos-rules-reference.md) — правила/сигналы
в формате «если условие → действие»;
[connproto-ddos-entities-reference.md](connproto-ddos-entities-reference.md) — словарь
сущностей (директивы, зоны, теги, поля лога, перечисления).

**Статус:** проектный контракт (целевое поведение), предшествует реализации.

**Формат.** Показаны иллюстративные фрагменты nginx-конфига (`http`/`server`) и YAML
для policy-ручки. Главное — структура и семантика, не точные значения: cap/таймауты
здесь — системные константы пула, не клиентская настройка.

**Чем эта ось особенная.** В отличие от [config-templates.md](config-templates.md), здесь
**нет конфига стадии каскада.** Это nginx-директивы, которые живут ниже
`access_by_lua`: они рвут/ограничивают соединение до того, как запрос дойдёт до Lua-каскада.
Lua здесь только наблюдает в log-фазе (`log_by_lua` → `bac_log`). Менять директивы
per-request из Lua нельзя — отсюда coarse-характер policy-ручки.

---

## Иерархия конфигов

```
http { … }                       ← глобальные таймауты + объявление зоны limit_conn + keepalive
server { … }                     ← применение limit_conn, listen http2 on, http2_max_concurrent_streams
build / Dockerfile               ← фиксация версии OpenResty/nginx ≥ 1.25.3 (Rapid Reset guard)
log_by_lua (bac_log)             ← наблюдение: $status/$request_time → тег slow_client/conn_flood
map $… → policy-ручка            ← опц., выбор жёсткой зоны limit_conn под attack_mode (per-host)
policy[host].attack_mode/strictness ← per-host knob, приходит из backend (не локальный файл)
```

---

## 1. Slow-attacks: таймауты (этап Baseline-директивы)

Самый дешёвый и срочный слой: чистый nginx, 0 Lua, ~80% эффекта. Срезает дефолтные 60s до
10–15s, чтобы рвать соединения, не завершающие заголовки/тело/чтение. Полностью обратимо.

```nginx
# http { } — глобальные таймауты приёма/отдачи (Baseline-директивы)

# Slowloris: клиент не дослал строку запроса + заголовки в окно → 408
client_header_timeout   15s;     # дефолт 60s — срезаем

# Slow POST: клиент медленно/никогда не завершает тело → 408
client_body_timeout     15s;

# Slow read: клиент медленно вычитывает ответ → обрыв соединения
send_timeout            15s;

# Осознанные буферы под заголовки (защита от header-abuse)
large_client_header_buffers 4 8k;
```

> **Гарантия для легитимных клиентов.** Solver шлёт <2KB, `client_body_buffer_size 8k`
> уже стоит — нормальный трафик с запасом укладывается в 15s. Срез бьёт только по
> slow-attacks. `client_max_body_size` задаётся осознанно на прокси-путях (в стенде
> сейчас — только на solver-локации).

---

## 2. Slow-attacks: зона `limit_conn` + keepalive (этап Baseline-директивы)

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
> `limit_conn_status` (503). Это видно в log-фазе как `$status=503` и порождает тег
> `conn_flood`. Cap — системная константа пула, клиент в дашборде его не настраивает.

---

## 3. HTTP/2 DoS: билд + директивы (этап HTTP/2 mitigation-аудит)

В основном свойство пропатченного билда + пара директив. Самостоятельный этап, не зависит
от Baseline.

```dockerfile
# Dockerfile / build — зафиксировать версию с Rapid Reset guard
# OpenResty/nginx >= 1.25.3 считает сброшенные-без-завершения HTTP/2-стримы
# и рвёт соединение при превышении (CVE-2023-44487 и родня).
FROM openresty/openresty:1.25.3.1-alpine   # пример: версия >= 1.25.3
```

```nginx
# server { } — HTTP/2-настройки

listen 443 ssl;
http2 on;                              # уже включено в стенде

# Лимит одновременных стримов в соединении (дефолт 128) — затюнить под профиль трафика
http2_max_concurrent_streams 128;

# keepalive_requests учитывается и для h2-мультиплекса
keepalive_requests 1000;

# Пороги CONTINUATION/PING/SETTINGS flood — задаются версией билда (см. changelog версии),
# отдельной директивой в конфиге могут не выражаться — это build-гарантия.
```

> ⚠️ Это HTTP/2 DoS-mitigation (E3), а не HTTP/2 fingerprint (E2). Frame-уровень
> не доходит до HTTP-семантики, каскад его не видит вовсе. fp (E2) — отдельная задача
> идентификации клиента, опционально даёт сигнал h2-abuse для репутации.

---

## 4. Observability: наблюдение в log-фазе (этап Observability)

Не конфиг митигации — наш Lua-хук, который превращает nginx-дроп в событие `bac_log`.
Переиспользует тот же контракт, что hygiene/reputation. Иллюстративно:

```nginx
# server { } / location { } — наблюдательный хук в log-фазе
log_by_lua_block {
    -- читаем то, что nginx отдал в log-фазе
    local status = tonumber(ngx.var.status)
    local rt     = tonumber(ngx.var.request_time)

    -- 408 от таймаутов заголовков/тела/чтения → slow_client
    if status == 408 then
        bac_log.emit{ tags = { "slow_client" }, request_time = rt }
        metrics.incr_by_ip_and_subnet("slow_client")   -- счётчик по IP / /24
    -- 503 (= limit_conn_status) → conn_flood
    elseif status == 503 then
        bac_log.emit{ tags = { "conn_flood" } }
        metrics.incr_by_ip_and_subnet("conn_flood")
    end
}
```

> **Ограничение наблюдаемости.** Видно только то, что nginx отдаёт в log-фазе
> (`$status`, `$request_time`, `$connection_requests`). Сам процесс «цежения» медленного
> соединения в реальном времени Lua не видит — фиксируется итог дропа. Счётчики по
> IP / /24 питают репутацию (G2) и через неё edge-ACL feed.

---

## 5. Policy-ручка: ужесточение под `attack_mode` (этап Policy-ручка, опционально)

Под `policy[host].attack_mode=on` / повышенной strictness — более жёсткая зона `limit_conn`
и/или ниже таймауты.

> ⚠️ Честное ограничение. nginx-директивы нельзя менять per-request из Lua.
> Реализация — `map`-driven выбор зоны per-host или грубый global-toggle, не плавная
> per-request подстройка. Этот этап может вовсе не делаться, если Baseline + Observability
> уже закрывают риск.

```nginx
# http { } — две зоны разной жёсткости + map-выбор по host

limit_conn_zone $binary_remote_addr zone=perip_normal:10m;
limit_conn_zone $binary_remote_addr zone=perip_strict:10m;

# attack_mode проецируется в переменную (источник — policy[host], приходит из backend)
map $host $conn_zone_for_host {
    default          perip_normal;
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
> `map`) или глобально, не per-request. Значения cap/таймаутов для жёсткой зоны — системные
> константы, как и в Baseline.

---

## Соглашения по staged rollout и заметки

1. **Baseline — первым и срочно.** Стенд уязвим из коробки (нет `limit_conn`, нет кастомных
   `client_*_timeout`/`send_timeout`). Baseline-директивы — самый дешёвый и срочный слой;
   полностью обратимы.
2. **Таймауты раскатывать с запасом.** Перед срезом до 10–15s убедиться по логам
   (`$request_time` легитимных запросов), что нормальный трафик укладывается с запасом —
   иначе ложные `408`.
3. **`limit_conn` cap калибровать по реальному профилю.** Слишком низкий cap бьёт по NAT/
   корпоративным выходам (много легит-клиентов за одним IP). Стартовать консервативно,
   следить за тегом `conn_flood` на легит-трафике.
4. **HTTP/2-аудит самостоятелен.** Фиксация версии билда ≥ 1.25.3 и тюнинг
   `http2_max_concurrent_streams` не зависят от slow-этапов; делать параллельно.
5. **Policy-ручка опциональна и coarse.** Не реализуется как per-request adaptive (nginx так
   не умеет). Делать только если Baseline + Observability недостаточны.
6. **Волюметрика L3/L4 — вне этих конфигов.** SYN/UDP/амплификация митигируется ниже
   OpenResty; наш максимум — поставка нарушителей в edge-ACL feed.

Порядок: Baseline-директивы → Observability → Policy-ручка (опц.); HTTP/2 mitigation-аудит —
самостоятельно. Самодостаточный разбор правил и сигналов —
[connproto-ddos-rules-reference.md](connproto-ddos-rules-reference.md); словарь сущностей —
[connproto-ddos-entities-reference.md](connproto-ddos-entities-reference.md).
