// Store — атомарный держатель *Data + детерминированный сборщик snapshot'ов
// для HTTP-ответа. Чтения lock-free через atomic.Pointer; запись (Replace)
// последовательная, заменяет указатель целиком — никаких частичных обновлений
// между каталогами не видно из-под чтения.
//
// Snapshot собирается на каждое чтение: при ~12 req/s (config-distribution
// §Channel C / Load) кэшировать ради экономии хэша смысла нет, а ETag-кэш
// добавил бы инвалидацию.
//
// Детерминизм payload'а нужен для ETag-стабильности и работает за счёт двух
// инвариантов:
//   - все срезы в Data отсортированы Normalize()'ом на входе (один раз на
//     load, не на каждый запрос — см. PR #42 review);
//   - все map'ы сериализуются через json.Marshal — encoding/json
//     документированно пишет ключи map'ов в лексикографическом порядке.

package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync/atomic"
)

// Snapshot — то, что отдаём в HTTP-ответ. Body уже сериализован; etag
// посчитан по нему же — детерминированно для одинаковой Data+site.
type Snapshot struct {
	Body    []byte
	ETag    string
	Version string
}

// Store — read-mostly хранилище. Создаётся с пустыми каталогами и
// Version=defaultVersion ("0.0.0"); сервер по этому версиону отвечает 503,
// пока Replace не положил реальный snapshot — иначе эдж залип бы на пустых
// данных, видя "успешный" 200 (см. server.handle).
type Store struct {
	data atomic.Pointer[Data]
	// loaded — отдельный сигнал "данные положены хотя бы раз" вместо сравнения
	// Version с defaultVersion. Иначе оператор, который легитимно ставит
	// `version: "0.0.0"` в YAML (bootstrap / pre-release), получал бы 503
	// до бесконечности — handler не различал бы "ещё не загружали" от "загрузили
	// данные с этим версионом" (PR #42 follow-up).
	loaded atomic.Bool
}

func NewStore() *Store {
	s := &Store{}
	s.data.Store(emptyData())
	return s
}

// Replace меняет данные целиком. Безопасно из любого числа горутин (но в
// реальной топологии писатель один — YAML-reloader / B4 db-poller).
// Нормализует d перед публикацией: сортирует все срезы и дедуплицирует ASN,
// чтобы build*-функции на hot-path просто читали уже подготовленный массив.
func (s *Store) Replace(d *Data) {
	if d == nil {
		d = emptyData()
	}
	normalize(d)
	s.data.Store(d)
	s.loaded.Store(true)
}

// IsLoaded возвращает true, когда Replace вызывался хотя бы один раз.
// Handler по нему решает 200 vs 503 — не по сравнению Version с защитной
// сентинелью, чтобы не падать на легитимном version: "0.0.0".
func (s *Store) IsLoaded() bool { return s.loaded.Load() }

// Snapshot собирает payload для (catalog, site). err != nil для неизвестного
// имени каталога или ошибки сериализации; handler разделяет 404 / 500.
//
// site="" — глобальный payload (для каталогов, где per-tenant не применим,
// payload идентичен запросу с любым site).
func (s *Store) Snapshot(catalog, site string) (Snapshot, error) {
	d := s.data.Load()
	if d == nil {
		// Не должно случаться — emptyData ставится в NewStore. Защита от
		// чужой попытки сунуть nil в atomic.Pointer.
		d = emptyData()
	}

	var (
		body []byte
		err  error
	)
	switch catalog {
	case "fp_blocklist":
		body, err = jsonBytes(d.FPBlocklist)
	case "ua_blacklist":
		body, err = buildUABlacklist(d, site)
	case "ip_blocklist":
		body, err = buildIPBlocklist(d, site)
	case "ip_whitelist":
		body, err = buildIPWhitelist(d, site)
	case "asn_datacenters":
		body = buildASNDatacenters(d) // ручная сборка ради числовой сортировки, ошибок нет
	case "verified_bot_ips":
		body, err = jsonBytes(d.VerifiedBotIPs)
	case "policy":
		body, err = buildPolicy(d, site)
	case "attack_mode":
		body, err = buildAttackMode(d, site)
	default:
		return Snapshot{}, errUnknownCatalog{name: catalog}
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("build %s: %w", catalog, err)
	}

	sum := sha256.Sum256(body)
	// Strong ETag (без слабого W/) — payload собран детерминированно, побайтовое
	// равенство = семантическое равенство, никаких whitespace-различий.
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	return Snapshot{Body: body, ETag: etag, Version: d.Version}, nil
}

// errUnknownCatalog различает 404 (имя не из списка) от 500 (сериализация
// упала): handler смотрит errors.As, чтобы не лить 500 при опечатке в URL.
type errUnknownCatalog struct{ name string }

func (e errUnknownCatalog) Error() string { return "unknown catalog: " + e.name }

// ----- builders -------------------------------------------------------------
//
// Каждый builder обязан быть детерминированным по содержимому Data+site —
// иначе ETag будет «дёргаться» на каждом запросе и If-None-Match сломается.

// buildUABlacklist собирает combined regex из глобальных UABlacklist +
// (если site задан и policy[site].UABlacklist непуст) кастомных паттернов
// клиента и отдаёт ОДНУ JSON-строку — ровно та форма, которую обещает
// config-distribution.md §"The 'catalog' concept" (shape = "combined regex
// string"). Edge парсит JSON, получает строку с regex'ом, компилирует её
// один раз на swap.
//
// Каждый паттерн валидируется в LoadYAML через regexp.Compile, так что в
// combined regex попадает только синтаксически корректный RE2.
func buildUABlacklist(d *Data, site string) ([]byte, error) {
	// Срезы уже отсортированы normalize(). Просто конкатенируем — порядок
	// "system, потом per-resource" фиксирован: если поменяем, не забыть про
	// X-Catalog-Version major.
	patterns := make([]string, 0, len(d.UABlacklist)+4)
	patterns = append(patterns, d.UABlacklist...)
	if site != "" {
		if p, ok := d.Policy[site]; ok {
			patterns = append(patterns, p.UABlacklist...)
		}
	}

	var combined string
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if combined != "" {
			combined += "|"
		}
		// Non-capturing group: нам не нужны $1/$2 на edge, но альтернация
		// должна биндиться к одному паттерну, не к произвольному `|` внутри.
		combined += "(?:" + p + ")"
	}
	return jsonBytes(combined)
}

func buildIPBlocklist(d *Data, site string) ([]byte, error) {
	// Системный ip_blocklist + per-resource policy[site].IPBlocklist. Эдж
	// различит источник по rule_source через отдельный лог-маппинг — здесь
	// просто объединяем; контракт payload — `{cidr: "block"}`.
	if site == "" {
		return jsonBytes(d.IPBlocklist)
	}
	p, ok := d.Policy[site]
	if !ok || len(p.IPBlocklist) == 0 {
		return jsonBytes(d.IPBlocklist)
	}
	out := make(map[string]string, len(d.IPBlocklist)+len(p.IPBlocklist))
	for k, v := range d.IPBlocklist {
		out[k] = v
	}
	for _, cidr := range p.IPBlocklist {
		out[cidr] = "block"
	}
	return jsonBytes(out)
}

func buildIPWhitelist(d *Data, site string) ([]byte, error) {
	// Системный + per-resource. Дедуп через set: оба источника могут
	// независимо иметь один и тот же CIDR (например, корпоративная подсеть).
	if site == "" {
		return jsonBytes(d.IPWhitelist)
	}
	p, ok := d.Policy[site]
	if !ok || len(p.IPWhitelist) == 0 {
		return jsonBytes(d.IPWhitelist)
	}
	seen := make(map[string]struct{}, len(d.IPWhitelist)+len(p.IPWhitelist))
	merged := make([]string, 0, len(d.IPWhitelist)+len(p.IPWhitelist))
	for _, c := range d.IPWhitelist {
		if _, dup := seen[c]; !dup {
			seen[c] = struct{}{}
			merged = append(merged, c)
		}
	}
	for _, c := range p.IPWhitelist {
		if _, dup := seen[c]; !dup {
			seen[c] = struct{}{}
			merged = append(merged, c)
		}
	}
	sort.Strings(merged) // обе ветки уже sorted из normalize, но merge порядок ломает
	return jsonBytes(merged)
}

// buildASNDatacenters пишет JSON-объект руками: ключи — числа,
// json.Marshal(map[uint32]int) выдал бы их в лексикографическом порядке
// ("10" < "2"), а контракт §В1 — числовой порядок (читаемее в diff'ах
// между версиями каталога).
func buildASNDatacenters(d *Data) []byte {
	asns := d.ASNDatacenters // уже sorted+deduped в normalize()
	buf := make([]byte, 0, len(asns)*16+2)
	buf = append(buf, '{')
	for i, asn := range asns {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, '"')
		buf = strconv.AppendUint(buf, uint64(asn), 10)
		buf = append(buf, '"', ':', '1')
	}
	buf = append(buf, '}')
	return buf
}

func buildPolicy(d *Data, site string) ([]byte, error) {
	if site != "" {
		// Per-tenant: один host. Отсутствие = пустой Policy, не 404: эдж
		// должен различать "host не зарегистрирован → дефолтная policy" и
		// "каталога вообще нет".
		if p, ok := d.Policy[site]; ok {
			return jsonBytes(p)
		}
		return jsonBytes(Policy{})
	}
	// Без site — полный map. На практике эдж всегда зовёт с site (он знает
	// $host), но контракт оставляет lookup-режим для дашборда [B10] / аудита.
	return jsonBytes(d.Policy)
}

func buildAttackMode(d *Data, site string) ([]byte, error) {
	// Single source-of-truth: policy[host].AttackMode. Дублирующего top-level
	// map'а больше нет — два источника создавали split-brain (OR-merge не
	// давал выключить флаг через один источник, если в другом он остался).
	// Emergency-override от B10 должен идти ТЕМ ЖЕ путём (записывая Policy),
	// тогда поведение наблюдаемо одним catalog'ом.
	if site != "" {
		on := false
		if p, ok := d.Policy[site]; ok {
			on = p.AttackMode
		}
		return jsonBytes(map[string]bool{"on": on})
	}
	// Без site — полная карта host→on. Включаем явный false тоже: дашборд
	// должен видеть "управляется, но выключен" отдельно от "не настроен".
	out := make(map[string]bool, len(d.Policy))
	for h, p := range d.Policy {
		out[h] = p.AttackMode
	}
	return jsonBytes(out)
}

// jsonBytes — обёртка над json.Marshal, чтобы вызывающий код был
// единообразен. Не паникует на ошибку: builders возвращают её наверх,
// handler отвечает 500 — это лучше, чем уронить процесс из-за нашей
// неожиданной структуры (PR #42 review: error path, not panic).
func jsonBytes(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	return b, nil
}
