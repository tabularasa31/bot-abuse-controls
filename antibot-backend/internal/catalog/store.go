// Store — атомарный держатель *Data + детерминированный сборщик snapshot'ов
// для HTTP-ответа. Чтения lock-free через atomic.Pointer; запись (Replace)
// последовательная, заменяет указатель целиком — никаких частичных обновлений
// между каталогами не видно из-под чтения.
//
// Snapshot собирается на каждое чтение: при ~12 req/s (config-distribution
// §Channel C / Load) кэшировать ради экономии хэша смысла нет, а ETag-кэш
// добавил бы инвалидацию.

package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// Snapshot — то, что отдаём в HTTP-ответ. Body уже сериализован; etag
// посчитан по нему же — детерминированно для одинаковой Data+site (см.
// сортировку ключей в build*).
type Snapshot struct {
	Body    []byte
	ETag    string
	Version string
}

// Store — read-mostly хранилище. Создаётся с пустыми каталогами и валидным
// Version="", любая операция чтения до Replace вернёт детерминированно
// пустой snapshot — HTTP-слой ответит 200 с пустым телом, не паникнет.
type Store struct {
	data atomic.Pointer[Data]
}

func NewStore() *Store {
	s := &Store{}
	s.data.Store(emptyData())
	return s
}

// Replace меняет данные целиком. Безопасно из любого числа горутин (но в
// реальной топологии писатель один — YAML-reloader / B4 db-poller).
func (s *Store) Replace(d *Data) {
	if d == nil {
		d = emptyData()
	}
	s.data.Store(d)
}

// Snapshot собирает payload для (catalog, site). ok=false для неизвестного
// имени каталога — handler ответит 404, не 200 с пустым телом (важно: 200
// "" неотличимо от "каталог пуст", и эдж бы залип на пустых данных).
//
// site="" — глобальный payload (для каталогов, где per-tenant не применим,
// payload идентичен запросу с любым site).
func (s *Store) Snapshot(catalog, site string) (Snapshot, bool) {
	d := s.data.Load()
	if d == nil {
		// Не должно случаться — emptyData ставится в NewStore. Защита от
		// чужой попытки сунуть nil в atomic.Pointer.
		d = emptyData()
	}

	var body []byte
	switch catalog {
	case "fp_blocklist":
		body = buildFPBlocklist(d)
	case "ua_blacklist":
		body = buildUABlacklist(d, site)
	case "ip_blocklist":
		body = buildIPBlocklist(d, site)
	case "ip_whitelist":
		body = buildIPWhitelist(d, site)
	case "asn_datacenters":
		body = buildASNDatacenters(d)
	case "verified_bot_ips":
		body = buildVerifiedBotIPs(d)
	case "policy":
		body = buildPolicy(d, site)
	case "attack_mode":
		body = buildAttackMode(d, site)
	default:
		return Snapshot{}, false
	}

	sum := sha256.Sum256(body)
	// Strong ETag (без слабого W/) — payload собран детерминированно, побайтовое
	// равенство = семантическое равенство, никаких whitespace-различий.
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	return Snapshot{Body: body, ETag: etag, Version: d.Version}, true
}

// ----- builders -------------------------------------------------------------
//
// Каждый builder обязан быть детерминированным по содержимому Data+site —
// иначе ETag будет «дёргаться» на каждом запросе и If-None-Match сломается.
// Поэтому везде sort.Strings/Sort'им ключи, не полагаясь на map-iteration.

func buildFPBlocklist(d *Data) []byte {
	return jsonObjectString(sortedKeysString(d.FPBlocklist), d.FPBlocklist)
}

// buildUABlacklist собирает combined regex из глобальных UABlacklist +
// (если site задан и policy[site].UABlacklist непуст) кастомных паттернов
// клиента и отдаёт ОДНУ JSON-строку — ровно та форма, которую обещает
// config-distribution.md §"The 'catalog' concept" (shape = "combined regex
// string"). Edge парсит JSON, получает goluang/lua-строку с regex'ом,
// компилирует её один раз на swap.
//
// Каждый паттерн валидируется в LoadYAML через regexp.Compile, так что
// в combined regex попадает только синтаксически корректный RE2.
func buildUABlacklist(d *Data, site string) []byte {
	system := append([]string(nil), d.UABlacklist...)
	sort.Strings(system)

	var perResource []string
	if site != "" {
		if p, ok := d.Policy[site]; ok {
			perResource = append(perResource, p.UABlacklist...)
			sort.Strings(perResource)
		}
	}

	all := make([]string, 0, len(system)+len(perResource))
	all = append(all, system...)
	all = append(all, perResource...)

	parts := make([]string, 0, len(all))
	for _, p := range all {
		if p == "" {
			continue
		}
		// Non-capturing group: нам не нужны $1/$2 на edge, но альтернация
		// должна биндиться к одному паттерну, не к произвольному `|` внутри.
		parts = append(parts, "(?:"+p+")")
	}
	return mustJSON(strings.Join(parts, "|"))
}

func buildIPBlocklist(d *Data, site string) []byte {
	// Системный ip_blocklist + per-resource policy[site].IPBlocklist. Эдж
	// различит источник по rule_source через отдельный лог-маппинг — здесь
	// просто объединяем; контракт payload — `{cidr: "block"}`.
	out := make(map[string]string, len(d.IPBlocklist))
	for k, v := range d.IPBlocklist {
		out[k] = v
	}
	if site != "" {
		if p, ok := d.Policy[site]; ok {
			for _, cidr := range p.IPBlocklist {
				out[cidr] = "block"
			}
		}
	}
	return jsonObjectString(sortedKeysString(out), out)
}

func buildIPWhitelist(d *Data, site string) []byte {
	// Аналогично blocklist — системный + per-resource. Дедуп через set.
	set := make(map[string]struct{}, len(d.IPWhitelist))
	for _, c := range d.IPWhitelist {
		set[c] = struct{}{}
	}
	if site != "" {
		if p, ok := d.Policy[site]; ok {
			for _, c := range p.IPWhitelist {
				set[c] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return mustJSON(out)
}

func buildASNDatacenters(d *Data) []byte {
	// Set ASN → 1 по контракту config-distribution. JSON-ключи — строки.
	keys := make([]string, 0, len(d.ASNDatacenters))
	seen := make(map[uint32]struct{}, len(d.ASNDatacenters))
	for _, asn := range d.ASNDatacenters {
		if _, dup := seen[asn]; dup {
			continue
		}
		seen[asn] = struct{}{}
		keys = append(keys, strconv.FormatUint(uint64(asn), 10))
	}
	sort.Slice(keys, func(i, j int) bool {
		// сортируем по числовому значению, не лексикографически — иначе
		// "10" < "2", и ETag в pair'е с числовой сортировкой в B4 разойдётся.
		ai, _ := strconv.ParseUint(keys[i], 10, 32)
		bj, _ := strconv.ParseUint(keys[j], 10, 32)
		return ai < bj
	})

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		buf.WriteString(k)
		buf.WriteString(`":1`)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

func buildVerifiedBotIPs(d *Data) []byte {
	return jsonObjectString(sortedKeysString(d.VerifiedBotIPs), d.VerifiedBotIPs)
}

func buildPolicy(d *Data, site string) []byte {
	if site != "" {
		// Per-tenant: один host. Отсутствие = пустой policy, не 404: эдж
		// должен различать "host не зарегистрирован → дефолтная policy" и
		// "каталога вообще нет".
		if p, ok := d.Policy[site]; ok {
			return mustJSON(p)
		}
		return mustJSON(Policy{})
	}
	// Без site — полный map. На практике эдж всегда зовёт с site (он знает
	// $host), но контракт оставляет lookup-режим для дашборда [B10] / аудита.
	return mustJSON(d.Policy)
}

func buildAttackMode(d *Data, site string) []byte {
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
		return mustJSON(map[string]bool{"on": on})
	}
	// Без site — полная карта host→on. Включаем явный false тоже: дашборд
	// должен видеть "управляется, но выключен" отдельно от "не настроен".
	out := make(map[string]bool, len(d.Policy))
	for h, p := range d.Policy {
		out[h] = p.AttackMode
	}
	return jsonObjectBool(sortedKeysBool(out), out)
}

// ----- json helpers ---------------------------------------------------------
//
// json.Marshal для map[string]X не гарантирует порядок ключей внутри одной
// версии Go, и хотя de-facto stdlib сортирует — лучше не зависеть. Свои
// маленькие хелперы дают побайтовую стабильность для строковых map'ов.

func sortedKeysString(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jsonObjectString(keys []string, m map[string]string) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeJSONString(&buf, k)
		buf.WriteByte(':')
		writeJSONString(&buf, m[k])
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

func jsonObjectBool(keys []string, m map[string]bool) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeJSONString(&buf, k)
		buf.WriteByte(':')
		if m[k] {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

func writeJSONString(buf *bytes.Buffer, s string) {
	// Используем encoding/json для эскейпинга — никаких ручных проб
	// (бэкслеши, контрол-символы, юникод).
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal(string) не возвращает ошибку для валидного UTF-8.
		// Падать тут — единственно честный путь: alternative — отдать
		// битый JSON в catalog, эдж его не распарсит, fail-stale поможет.
		panic(fmt.Sprintf("json.Marshal(string) returned error: %v", err))
	}
	buf.Write(b)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("json.Marshal: %v", err))
	}
	return b
}
