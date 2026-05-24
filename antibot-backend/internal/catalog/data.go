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
	"net/netip"
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
	VerifiedBotIPs map[string]string `yaml:"verified_bot_ips"` // IP → "<status>:<family>" where status ∈ {verified, rejected}, family ∈ {google, bing, yandex, ddg}. Отсутствие ключа = provisional (см. vision §Шаг 2.2).
	Policy         map[string]Policy `yaml:"policy"`           // host → policy (включая attack_mode)
}

// Policy — per-resource настройки одного host'a. ВСЕ поля без omitempty:
// контракт `/catalog/policy?site=…` обещает map(host → policy json) c
// предсказуемой формой; consumer (дашборд/edge) должен видеть "field = zero"
// и "field absent" одинаково, не различая. Если поле появится позже —
// заведём для него отдельный major bump Version.
type Policy struct {
	Mode         string     `yaml:"mode" json:"mode"`                   // shadow / active
	Strictness   string     `yaml:"strictness" json:"strictness"`       // standard / permissive
	UABlacklist  []string   `yaml:"ua_blacklist" json:"ua_blacklist"`   // кастомные regex клиента
	IPWhitelist  []string   `yaml:"ip_whitelist" json:"ip_whitelist"`   // per-resource allow CIDR
	IPBlocklist  []string   `yaml:"ip_blocklist" json:"ip_blocklist"`   // per-resource deny CIDR
	ASNBlock     []uint32   `yaml:"asn_block" json:"asn_block"`         // per-resource deny ASN
	GeoWhitelist []string   `yaml:"geo_whitelist" json:"geo_whitelist"` // если задан — все остальные блокируются
	RateRules    []RateRule `yaml:"rate_rules" json:"rate_rules"`       // клиентские per-path rate-rules
	AttackMode   bool       `yaml:"attack_mode" json:"attack_mode"`     // единственный источник; map'а сверху больше нет
}

// RateRule — одна клиентская rate-rule из docs/product/config-templates.md
// §"policy/<host>.yaml". На стенде Lua пока не читает это поле (edge B11);
// backend хранит и отдаёт as-is для дашборда [B10] и для будущих фаз.
type RateRule struct {
	Path    string   `yaml:"path" json:"path"`
	Methods []string `yaml:"methods" json:"methods"`
	RPS     int      `yaml:"rps" json:"rps"`
	Burst   int      `yaml:"burst" json:"burst"`
	Action  string   `yaml:"action" json:"action"` // block | challenge | log_only
}

// PoolDefault — то, что отдаётся для незарегистрированного host'a:
// "новый домен без записи → дефолт пула (mode=shadow, observe-only)"
// (config-distribution §"Per-resource lookup", задача B4). Реализована
// как функция, а не как глобальная переменная: каждый вызов даёт новый
// slice'ный nil-zero — никто из вызывающих не может случайно мутировать
// общий объект.
func PoolDefault() Policy {
	return Policy{
		Mode:         "shadow",
		Strictness:   "standard",
		UABlacklist:  []string{},
		IPWhitelist:  []string{},
		IPBlocklist:  []string{},
		ASNBlock:     []uint32{},
		GeoWhitelist: []string{},
		RateRules:    []RateRule{},
	}
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

	if err := Validate(d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Каноничный вид сразу на выходе из LoadYAML: тесты и тулинг, который
	// читает результат напрямую (не через Store.Replace), получают тот же
	// порядок и тот же дедуп, что увидит build*-слой.
	normalize(d)
	return d, nil
}

// normalize приводит Data к каноничному виду: сортирует все срезы и
// дедуплицирует их (для детерминизма payload'а и стабильности ETag —
// две одинаковые записи в YAML не должны раздувать combined regex и не
// должны давать разный ETag по сравнению с одной записью).
//
// Вызывается из LoadYAML (источник правды для in-memory v1) и из
// Store.Replace (защитный slot — на случай, если данные пришли не из
// LoadYAML, например из B4 pgx-loader'а). Идемпотентен.
func normalize(d *Data) {
	// Системные slice'ы: dedup+sort + nil-coerce. Без ensure* json.Marshal
	// эмитил бы `null` на пустой БД (DB-loader не инициализирует пустые
	// срезы — append-loop пуст), и ETag дрейфил бы между «никогда не было
	// записей» и «была одна, удалили». PR #43 review (follow-up).
	d.UABlacklist = ensureStringSlice(dedupSortStrings(d.UABlacklist))
	d.IPWhitelist = ensureStringSlice(dedupSortStrings(d.IPWhitelist))
	d.ASNDatacenters = ensureUint32Slice(dedupSortUint32(d.ASNDatacenters))
	for h, p := range d.Policy {
		// Все []T поля: dedup+sort, потом nil → пустой slice. Coerce nil →
		// `[]T{}` критичен для JSON-стабильности: операторская запись
		// `ua_blacklist = 'null'::jsonb` через DB-loader приходит как
		// nil-slice; json.Marshal сериализует её как `null`, ETag отличается
		// от логически эквивалентной записи с пустым массивом / от
		// `PoolDefault()`. Закрываем PR #43 review (Angle A).
		p.UABlacklist = ensureStringSlice(dedupSortStrings(p.UABlacklist))
		p.IPWhitelist = ensureStringSlice(dedupSortStrings(p.IPWhitelist))
		p.IPBlocklist = ensureStringSlice(dedupSortStrings(p.IPBlocklist))
		p.GeoWhitelist = ensureStringSlice(dedupSortStrings(p.GeoWhitelist))
		p.ASNBlock = ensureUint32Slice(dedupSortUint32(p.ASNBlock))
		// RateRules — порядок задаётся оператором (приоритет правил),
		// сортировать нельзя; дедуп тоже не делаем (две одинаковые
		// записи могли быть осознанным повтором).
		if p.RateRules == nil {
			p.RateRules = []RateRule{}
		}
		d.Policy[h] = p
	}
}

func ensureStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func ensureUint32Slice(s []uint32) []uint32 {
	if s == nil {
		return []uint32{}
	}
	return s
}

func dedupSortStrings(s []string) []string {
	if len(s) < 2 {
		return s
	}
	sort.Strings(s)
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
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

// Validate проверяет:
//   - UA-regex (системные и per-host) через regexp.Compile;
//   - CIDR-строки (системные ip_blocklist / ip_whitelist и per-host
//     варианты) через `ValidateCIDR`, которая повторяет терпимость
//     lua-resty-ipmatcher: голый IP без `/N` принимается как host-route
//     (/32 для v4, /128 для v6), а CIDR с заданными host-битами
//     (`10.0.0.5/8`) — тоже валиден, ipmatcher всё равно их маскирует.
//
// Regex: RE2-grammar — не PCRE, но edge тоже на ngx.re (PCRE) с общим
// подмножеством; синтаксические ошибки (`bot[a-z`, unbalanced `(`,
// trailing `\`) ловятся одинаково. Если edge захочет PCRE-specific фичу
// (lookarounds), её нужно гейтить в спеке отдельно.
//
// CIDR: миграции 0001 НЕ держат `inet`-колонки (комментарий в схеме:
// "validation lives in the loader" — PR #43 review закрыл это обещание).
// Валидация специально симметрична edge'у: иначе backend стал бы строже,
// и оператор, вставивший `203.0.113.5` без `/32`, ловил бы fail-stale
// несмотря на то, что ipmatcher принял бы запись.
//
// Экспортирована, чтобы любой источник *Data (LoadYAML, dbloader.Load,
// будущий B10 admin API) обязан был дёргать её до Store.Replace —
// fail-stale работает только если битый паттерн ловится ДО публикации.
func Validate(d *Data) error {
	for i, p := range d.UABlacklist {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("ua_blacklist[%d]: invalid regex %q: %w", i, p, err)
		}
	}
	for cidr := range d.IPBlocklist {
		if err := ValidateCIDR(cidr); err != nil {
			return fmt.Errorf("ip_blocklist[%q]: %w", cidr, err)
		}
	}
	for i, cidr := range d.IPWhitelist {
		if err := ValidateCIDR(cidr); err != nil {
			return fmt.Errorf("ip_whitelist[%d] %q: %w", i, cidr, err)
		}
	}
	for host, pol := range d.Policy {
		for i, p := range pol.UABlacklist {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("policy[%s].ua_blacklist[%d]: invalid regex %q: %w", host, i, p, err)
			}
		}
		for i, cidr := range pol.IPBlocklist {
			if err := ValidateCIDR(cidr); err != nil {
				return fmt.Errorf("policy[%s].ip_blocklist[%d] %q: %w", host, i, cidr, err)
			}
		}
		for i, cidr := range pol.IPWhitelist {
			if err := ValidateCIDR(cidr); err != nil {
				return fmt.Errorf("policy[%s].ip_whitelist[%d] %q: %w", host, i, cidr, err)
			}
		}
	}
	return nil
}

// ValidateCIDR принимает либо «сырой» IP («1.2.3.4», «2001:db8::1»),
// либо префикс («10.0.0.0/8», «10.0.0.5/8» с заданными host-битами).
// Это симметрично lua-resty-ipmatcher на edge: тот принимает то же
// подмножество и сам маскирует host-биты. netip.ParsePrefix отдельно от
// netip.ParseAddr строже, поэтому пробуем оба. Экспортирована для
// переиспользования в [internal/antibotapi] (B10): admin-мутация должна
// валидировать вход тем же предикатом, что и reloader, иначе любая запись
// от dashboard'а уронит следующий тик reloader'a через catalog.Validate.
func ValidateCIDR(s string) error {
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP/CIDR")
}
