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

// HasVerifiedBotIP — есть ли запись (verified ИЛИ rejected) для IP в
// каталоге verified_bot_ips. rDNS-воркер (B7) использует это, чтобы
// не дёргать DNS повторно — отсутствие записи = ещё не проверяли
// (provisional на edge); наличие любого статуса = уже знаем verdict
// в пределах TTL, перепроверять нет смысла.
//
// Lock-free: data.Load() атомарный, map[string]string Replace'ом
// меняется целиком, читать без локов безопасно.
func (s *Store) HasVerifiedBotIP(ip string) bool {
	d := s.data.Load()
	if d == nil {
		return false
	}
	_, ok := d.VerifiedBotIPs[ip]
	return ok
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
	case "tls_fp_blocklist":
		body, err = buildTLSFPBlocklist(d)
	case "ua_blacklist":
		body, err = buildUABlacklist(d, site)
	case "ip_blocklist":
		body, err = buildIPBlocklist(d, site)
	case "ip_whitelist":
		body, err = buildIPWhitelist(d, site)
	case "asn_datacenters":
		body = buildASNDatacenters(d) // ручная сборка ради числовой сортировки, ошибок нет
	case "tls_fp_catalog":
		body, err = buildTLSFPCatalog(d)
	case "tls_fp_browser_profiles":
		body, err = buildTLSFPBrowserProfiles(d)
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

// buildUABlacklist собирает combined regex по статусам и отдаёт JSON-объект
// `{"active": "<combined>", "staging": "<combined>"}` (A11). Раньше форма
// была одной combined-regex строкой (config-distribution.md §"The 'catalog'
// concept"); чтобы доставлять staging-паттерны (эдж матчит их отдельным
// combined regex, пишет staging_match, НЕ блокирует), payload стал объектом
// с двумя строками. Изменение wire-схемы — минорное (X-Catalog-Version
// 1.2.0), edge-парсер обновляется в том же изменении.
//
//   - active  — глобальные UABlacklist + (если site задан) per-resource
//     policy[site].UABlacklist. Эдж компилирует и при матче → verdict=block.
//   - staging — только системные staging-паттерны (per-resource policy —
//     runtime state, staged rollout к нему не применяется). Эдж пишет
//     staging_match: ["ua_blacklist:<pattern>"], без verdict.
//
// Каждый паттерн валидируется в Validate через regexp.Compile, так что в
// combined regex попадает только синтаксически корректный RE2.
func buildUABlacklist(d *Data, site string) ([]byte, error) {
	// Срезы уже отсортированы normalize(). Просто конкатенируем — порядок
	// "system, потом per-resource" фиксирован: если поменяем, не забыть про
	// X-Catalog-Version major.
	active := make([]string, 0, len(d.UABlacklist)+4)
	active = append(active, d.UABlacklist...)
	if site != "" {
		if p, ok := d.Policy[site]; ok {
			active = append(active, p.UABlacklist...)
		}
	}
	out := map[string]string{
		"active":  combineRegex(active),
		"staging": combineRegex(d.UABlacklistStaging),
	}
	return jsonBytes(out)
}

// combineRegex склеивает паттерны в одну альтернацию `(?:p1)|(?:p2)|…`.
// Non-capturing group: нам не нужны $1/$2 на edge, но альтернация должна
// биндиться к одному паттерну, не к произвольному `|` внутри. Пустой вход
// → "" (эдж трактует пустую строку как «нет паттернов»).
func combineRegex(patterns []string) string {
	var combined string
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if combined != "" {
			combined += "|"
		}
		combined += "(?:" + p + ")"
	}
	return combined
}

// buildTLSFPBlocklist кодирует каждую запись как "<status>:block" (A11),
// симметрично tls_fp_catalog / verified_bot_ips: shared_dict на эдже хранит
// готовую строку без per-entry JSON-разбора. Вердикт для этого каталога
// всегда block; статус разводит active (эдж эмитит verdict=block) vs staging
// (эдж пишет staging_match, не блокирует). Edge парсит split-по-первой-`:`.
func buildTLSFPBlocklist(d *Data) ([]byte, error) {
	out := make(map[string]string, len(d.TLSFPBlocklist))
	for fp, status := range d.TLSFPBlocklist {
		out[fp] = status + ":block"
	}
	return jsonBytes(out)
}

func buildIPBlocklist(d *Data, site string) ([]byte, error) {
	// Системный ip_blocklist + per-resource policy[site].IPBlocklist. Эдж
	// различит источник по rule_source через отдельный лог-маппинг — здесь
	// просто объединяем; контракт payload — `{cidr: "<status>:block"}` (A11):
	// статус разводит active (verdict=block) vs staging (staging_match без
	// блокировки). Системные записи несут свой status; per-resource всегда
	// active (policy — runtime state, staged rollout к нему не применяется).
	out := make(map[string]string, len(d.IPBlocklist)+4)
	for cidr, status := range d.IPBlocklist {
		out[cidr] = status + ":block"
	}
	if site != "" {
		if p, ok := d.Policy[site]; ok {
			for _, cidr := range p.IPBlocklist {
				out[cidr] = "active:block"
			}
		}
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
		// Per-tenant: один host. Отсутствие записи = дефолт пула из B4
		// (mode=shadow, observe-only), не 404 и не пустой Policy{} —
		// edge должен сразу видеть валидный mode и не падать на "" в
		// switch'е по режиму. См. PoolDefault и config-distribution.md
		// §"Per-resource lookup — keyed by Host".
		if p, ok := d.Policy[site]; ok {
			return jsonBytes(p)
		}
		return jsonBytes(PoolDefault())
	}
	// Без site — полный map. На практике эдж всегда зовёт с site (он знает
	// $host), но контракт оставляет lookup-режим для дашборда [B10] / аудита.
	return jsonBytes(d.Policy)
}

// buildTLSFPCatalog кладёт каждую запись в payload как composite string
// `<status>:<family>` — симметрично verified_bot_ips ("<status>:<family>"),
// чтобы shared_dict на эдже хранил готовое значение без per-entry JSON-
// разбора. Edge парсит split-по-первой-`:` и решает active vs staging
// своей логикой (build_catalog в tls_fp.lua возвращает (active, staging) tuple).
func buildTLSFPCatalog(d *Data) ([]byte, error) {
	out := make(map[string]string, len(d.TLSFPCatalog))
	for hb, entry := range d.TLSFPCatalog {
		out[hb] = entry.Status + ":" + entry.Family
	}
	return jsonBytes(out)
}

// buildTLSFPBrowserProfiles — то же composite-кодирование, но во второй
// позиции число (десятичная строка). Edge на cipher_count числовое
// сравнение, поэтому tonumber на стороне Lua.
func buildTLSFPBrowserProfiles(d *Data) ([]byte, error) {
	out := make(map[string]string, len(d.TLSFPBrowserProfiles))
	for family, prof := range d.TLSFPBrowserProfiles {
		out[family] = prof.Status + ":" + strconv.Itoa(prof.ExpectedCipherCnt)
	}
	return jsonBytes(out)
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
