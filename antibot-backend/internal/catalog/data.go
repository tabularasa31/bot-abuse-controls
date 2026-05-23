// Типизированные данные восьми каталогов Channel C, который backend отдаёт
// edge'ам по контракту из docs/architecture/config-distribution.md
// (§"The 'catalog' concept"). Здесь только in-memory представление и YAML-
// загрузчик; HTTP-доставка — в server.go, snapshot-сборка — в store.go.
//
// Per-resource данные (`policy`, кастомные UA-паттерны, attack_mode) живут
// в map[host]Policy; общие списки — в плоских структурах. По решению config-
// distribution per-resource ключ — `host`, не `cdn_resource_id`.
package catalog

import (
	"fmt"
	"os"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// defaultVersion — semver, который Store отдаёт до первой загрузки. Он же
// уходит в X-Catalog-Version (заголовок ставится всегда — контракт §В1).
// "0.0.0" по semver значит "пред-релиз / пусто"; edge может опираться на
// смену major-сегмента, чтобы понять breaking-change схемы payload'а.
const defaultVersion = "0.0.0"

// Data — снимок всего хранилища каталогов. Меняется целиком атомарно через
// Store.Replace; ссылки на старую *Data корректны на время чтения, никаких
// частичных обновлений между каталогами нет.
type Data struct {
	// Version — semver, кладётся в X-Catalog-Version всех ответов.
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
	Policy         map[string]Policy `yaml:"policy"`           // host → policy (включая attack_mode)
}

// Policy — per-resource настройки одного host'a. ВСЕ поля без omitempty:
// контракт `/catalog/policy?site=…` обещает map(host → policy json) c
// предсказуемой формой; consumer (дашборд/edge) должен видеть "field = zero"
// и "field absent" одинаково, не различая. Если поле появится позже —
// заведём для него отдельный major bump Version.
type Policy struct {
	Mode         string   `yaml:"mode" json:"mode"`                 // shadow / active
	Strictness   string   `yaml:"strictness" json:"strictness"`     // standard / permissive
	UABlacklist  []string `yaml:"ua_blacklist" json:"ua_blacklist"` // кастомные regex клиента
	IPWhitelist  []string `yaml:"ip_whitelist" json:"ip_whitelist"` // per-resource allow CIDR
	IPBlocklist  []string `yaml:"ip_blocklist" json:"ip_blocklist"` // per-resource deny CIDR
	ASNBlock     []uint32 `yaml:"asn_block" json:"asn_block"`       // per-resource deny ASN
	GeoWhitelist []string `yaml:"geo_whitelist" json:"geo_whitelist"`
	AttackMode   bool     `yaml:"attack_mode" json:"attack_mode"` // единственный источник; map'а сверху больше нет
}

// emptyData — детерминированный нуль для Store до первого Replace.
// Version=defaultVersion (не ""), чтобы X-Catalog-Version был валидным
// semver'ом даже на эмпти-инстансе — edge не должен различать "header
// present" vs "header absent" по wire.
func emptyData() *Data {
	return &Data{
		Version:        defaultVersion,
		FPBlocklist:    map[string]string{},
		UABlacklist:    nil,
		IPBlocklist:    map[string]string{},
		IPWhitelist:    nil,
		ASNDatacenters: nil,
		VerifiedBotIPs: map[string]string{},
		Policy:         map[string]Policy{},
	}
}

// LoadYAML — загрузчик v1: один YAML-файл со всеми каталогами. Postgres-
// бэкенд (B4) заменит это, контракт Store.Replace останется тем же.
//
// Strict: KnownFields => true, чтобы опечатки в ключе (`fp_block_list`)
// валились на проде, а не молча превращались в пустой каталог.
//
// Regex-валидация: каждый паттерн ua_blacklist (системный + per-resource)
// прогоняется через regexp.Compile перед публикацией. Одна сломанная
// строка в YAML иначе доедет до edge внутри combined regex и положит
// всю UA-стадию по всем pull'ам — лучше упасть на старте.
func LoadYAML(path string) (*Data, error) {
	f, err := os.Open(path) //nolint:gosec // путь приходит из конфига оператора, не из запроса
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Декодируем в "сырой" Data (не emptyData): дефолтный Version в YAML
	// допустим не должен, операторская ошибка "забыл version:" обязана
	// падать. defaultVersion применяется ТОЛЬКО к Store до первого Replace.
	d := &Data{}
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

	if err := validatePatterns(d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// normalize приводит Data к каноничному виду: сортирует все срезы (для
// детерминизма payload'а и стабильности ETag) и дедуплицирует ASN'ы.
// Вызывается один раз при загрузке (LoadYAML) и в Store.Replace — на
// hot-path build*-функции читают уже подготовленные данные.
func normalize(d *Data) {
	sortStrings(d.UABlacklist)
	sortStrings(d.IPWhitelist)
	d.ASNDatacenters = dedupSortUint32(d.ASNDatacenters)
	for h, p := range d.Policy {
		sortStrings(p.UABlacklist)
		sortStrings(p.IPWhitelist)
		sortStrings(p.IPBlocklist)
		sortStrings(p.GeoWhitelist)
		p.ASNBlock = dedupSortUint32(p.ASNBlock)
		d.Policy[h] = p
	}
}

func sortStrings(s []string) {
	if len(s) > 1 {
		sort.Strings(s)
	}
}

func dedupSortUint32(s []uint32) []uint32 {
	if len(s) < 2 {
		return s
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// validatePatterns прогоняет каждый regex (системный и per-resource) через
// regexp.Compile. RE2-grammar — не PCRE, но edge тоже на ngx.re (PCRE) с
// общим подмножеством; синтаксические ошибки (`bot[a-z`, unbalanced `(`,
// trailing `\`) ловятся одинаково. Если edge захочет PCRE-specific фичу
// (lookarounds), её нужно гейтить в спеке отдельно — пока консервативно
// бьёмся за RE2-валидность.
func validatePatterns(d *Data) error {
	for i, p := range d.UABlacklist {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("ua_blacklist[%d]: invalid regex %q: %w", i, p, err)
		}
	}
	for host, pol := range d.Policy {
		for i, p := range pol.UABlacklist {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("policy[%s].ua_blacklist[%d]: invalid regex %q: %w", host, i, p, err)
			}
		}
	}
	return nil
}
