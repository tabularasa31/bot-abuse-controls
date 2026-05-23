// Типизированные данные восьми каталогов Channel C, который backend отдаёт
// edge'ам по контракту из docs/architecture/config-distribution.md
// (§"The 'catalog' concept"). Здесь только in-memory представление и YAML-
// загрузчик; HTTP-доставка — в server.go, snapshot-сборка — в store.go.
//
// Per-resource данные (`policy`, `attack_mode`, кастомные UA-паттерны) живут
// в map[host]…; общие списки — в плоских структурах. По решению config-
// distribution per-resource ключ — `host`, не `cdn_resource_id`.
package catalog

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Data — снимок всего хранилища каталогов. Меняется целиком атомарно через
// Store.Replace; ссылки на старую *Data корректны на время чтения, никаких
// частичных обновлений между каталогами нет.
type Data struct {
	// Version — semver, кладётся в X-Catalog-Version всех ответов. Контракт §В1:
	// edge сравнивает major, чтобы детектить breaking-change схемы payload.
	// Меняется руками или дашбордом, не автогенерация: для эджа важно различать
	// "схема та же, контент новый" (только ETag меняется) и "схема новая"
	// (parser нужно обновлять). За свежесть контента отвечает ETag, не Version.
	Version string `yaml:"version"`

	FPBlocklist    map[string]string `yaml:"fp_blocklist"`     // fp → "block"
	UABlacklist    []string          `yaml:"ua_blacklist"`     // глобальные regex-паттерны
	IPBlocklist    map[string]string `yaml:"ip_blocklist"`     // CIDR → "block"
	IPWhitelist    []string          `yaml:"ip_whitelist"`     // CIDR (системный)
	ASNDatacenters []uint32          `yaml:"asn_datacenters"`  // ASN-номера
	VerifiedBotIPs map[string]string `yaml:"verified_bot_ips"` // IP → "google|bing|yandex|ddg"
	Policy         map[string]Policy `yaml:"policy"`           // host → policy
	AttackMode     map[string]bool   `yaml:"attack_mode"`      // host → on/off
}

// Policy — per-resource настройки одного host'a. Минимум полей, которых
// сейчас касается B3-контракт: UA-расширения для combined regex и IP-листы
// для per_resource rule_source (entities-reference §"Каталоги/policy"). Остальное
// (mode, strictness, asn_block, geo_whitelist, rate_rules) добавим под нужду
// в дашборде [B10] и edge-стороне A1/A2/A3/A4/A5.
type Policy struct {
	Mode         string   `yaml:"mode,omitempty"`          // shadow / active
	Strictness   string   `yaml:"strictness,omitempty"`    // standard / permissive
	UABlacklist  []string `yaml:"ua_blacklist,omitempty"`  // кастомные regex клиента
	IPWhitelist  []string `yaml:"ip_whitelist,omitempty"`  // per-resource allow CIDR
	IPBlocklist  []string `yaml:"ip_blocklist,omitempty"`  // per-resource deny CIDR
	ASNBlock     []uint32 `yaml:"asn_block,omitempty"`     // per-resource deny ASN
	GeoWhitelist []string `yaml:"geo_whitelist,omitempty"` // ISO 3166-1 alpha-2
	AttackMode   bool     `yaml:"attack_mode,omitempty"`   // дублирует AttackMode[host]; см. ниже
}

// emptyData — нулевая Data, чтобы Store до первого Replace выдавал детермини-
// рованный пустой ответ, а не nil-map-панику в build*. Version пустой
// специально: эдж по `""` поймёт "no data loaded yet" и не закроет cold-start
// раньше времени.
func emptyData() *Data {
	return &Data{
		FPBlocklist:    map[string]string{},
		UABlacklist:    nil,
		IPBlocklist:    map[string]string{},
		IPWhitelist:    nil,
		ASNDatacenters: nil,
		VerifiedBotIPs: map[string]string{},
		Policy:         map[string]Policy{},
		AttackMode:     map[string]bool{},
	}
}

// LoadYAML — загрузчик v1: один YAML-файл со всеми каталогами. Postgres-
// бэкенд (B4) заменит это, контракт Store.Replace останется тем же.
//
// Strict: KnownFields => true, чтобы опечатки в ключе (`fp_block_list`)
// валились на проде, а не молча превращались в пустой каталог.
func LoadYAML(path string) (*Data, error) {
	f, err := os.Open(path) //nolint:gosec // путь приходит из конфига оператора, не из запроса
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	d := emptyData()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(d); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if d.Version == "" {
		// Без semver edge не сможет защититься от breaking schema change.
		// Лучше упасть на старте, чем тянуть пустой X-Catalog-Version.
		return nil, fmt.Errorf("%s: required field 'version' missing", path)
	}
	// Нормализуем nil-maps, которые decoder оставит, если ключа нет в YAML —
	// иначе build* словит nil-map в range/lookup.
	if d.FPBlocklist == nil {
		d.FPBlocklist = map[string]string{}
	}
	if d.IPBlocklist == nil {
		d.IPBlocklist = map[string]string{}
	}
	if d.VerifiedBotIPs == nil {
		d.VerifiedBotIPs = map[string]string{}
	}
	if d.Policy == nil {
		d.Policy = map[string]Policy{}
	}
	if d.AttackMode == nil {
		d.AttackMode = map[string]bool{}
	}
	return d, nil
}
