// Package filesource — git-репо каталогов как источник медленных
// каталогов Channel C (ADR-006).
//
// Контракт совпадает с тем, что раньше делал dbloader для медленных
// таблиц: на каждом тике reloader'а Load возвращает *catalog.SlowData;
// reloader мерджит её с runtime-частью (verified_bot_ips, policy) из
// БД и публикует в Store. Валидация regex/CIDR — та же, что в dbloader:
// одна битая запись валит весь Load (fail-stale), Store не трогаем.
//
// Структура файлов:
//
//	<dir>/version                 — singleton semver (text, одна строка).
//	<dir>/tls_fp_blocklist.yaml   — map(fp → "active"|"staging"); endpoint
//	                                `/catalog/fp_blocklist` (wire-имя historical).
//	<dir>/ua_blacklist.yaml       — map(pattern → "active"|"staging").
//	<dir>/ip_blocklist.yaml       — map(cidr → "active"|"staging").
//	<dir>/ip_whitelist.yaml       — sequence of cidr (без status).
//	<dir>/asn_datacenters.yaml    — sequence of uint32 (без status).
//
// `status` для каталогов с поддержкой staged rollout:
//   - "active" — попадает в Channel C payload.
//   - "staging" — читается из файла, валидируется, но в SlowData НЕ кладётся.
//     Эдж эти записи увидит, когда A11 будет расширен на новые каталоги
//     (отдельным PR / задачей).
//
// Пустой файл / только комментарии = пустой каталог. Отсутствующий файл —
// ошибка (защита от опечатки в имени).
package filesource

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
)

// Список файлов, которые мы трекаем для mtime-cache. Если добавляется новый
// каталог — добавь сюда и в Load().
var trackedFiles = []string{
	"version",
	// tls_fp_blocklist.yaml — vision/entities-reference.md называет этот
	// каталог `tls_fp_blocklist` (L3 TLS-fp blocking). На wire-уровне
	// (Channel C endpoint, shared_dict на эдже) и в catalog.Data поле
	// исторически зовётся `fp_blocklist` — обе именования живут параллельно,
	// для file-system источника выбираем doc-имя. Endpoint
	// `/catalog/fp_blocklist` НЕ переименован — это сломало бы edge без
	// функциональной выгоды.
	"tls_fp_blocklist.yaml",
	"ua_blacklist.yaml",
	"ip_blocklist.yaml",
	"ip_whitelist.yaml",
	"asn_datacenters.yaml",
	"tls_fp_catalog.yaml",
	"tls_fp_browser_profiles.yaml",
}

// statusActive — единственное значение status, которое попадает в активный
// payload. Всё остальное (включая "staging") отфильтровывается. Список
// допустимых значений валидируется в parseStatusMap.
const statusActive = "active"

// validStatuses — что считаем валидным значением status. Любое другое
// значение в файле валит Load: симметрично DB-схеме (CHECK (status IN
// ('active','staging'))).
var validStatuses = map[string]struct{}{
	"active":  {},
	"staging": {},
}

type Loader struct {
	dir    string
	mtimes map[string]time.Time
}

// New создаёт Loader, привязанный к каталогу dir. dir может ещё не
// существовать на момент New — проверка отложена до Load(), чтобы
// конструктор оставался дешёвым и не имел error-возврата.
func New(dir string) *Loader {
	return &Loader{
		dir:    dir,
		mtimes: map[string]time.Time{},
	}
}

// Dir возвращает корневую папку каталогов. Полезно для логов / health-checks.
func (l *Loader) Dir() string { return l.dir }

// Changed возвращает true, если mtime хотя бы одного файла отличается от
// закешированного, ЛИБО кеш ещё пуст (первый вызов). Чтение mtime не
// валит ошибку — пропавший файл попадёт в Load как явный fail-stale там,
// reloader увидит ошибку, оператор увидит её в логах + reload_failures.
func (l *Loader) Changed() bool {
	if len(l.mtimes) == 0 {
		return true
	}
	for _, name := range trackedFiles {
		path := filepath.Join(l.dir, name)
		info, err := os.Stat(path)
		if err != nil {
			// Файл пропал между тиками — это изменение, пусть Load его
			// поймает и вернёт ошибку (fail-stale + видимая причина).
			return true
		}
		if cached, ok := l.mtimes[name]; !ok || !info.ModTime().Equal(cached) {
			return true
		}
	}
	return false
}

// Load читает все каталоги, валидирует и возвращает *catalog.SlowData с
// активными записями. На любой ошибке (IO, parse, validate) возвращает
// её — caller (reloader) НЕ трогает Store, эдж продолжает работать с
// предыдущим хорошим payload'ом. Обновляет mtime-cache только при успехе:
// частичный успех (например, version прочли, ua_blacklist упал) не
// должен «потерять» сигнал об изменении на следующем тике.
func (l *Loader) Load() (*catalog.SlowData, error) {
	mtimes := make(map[string]time.Time, len(trackedFiles))

	// version: текстовый файл, не YAML. Trim — допустим trailing newline.
	versionRaw, vmtime, err := readFile(l.dir, "version")
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	version := strings.TrimSpace(string(versionRaw))
	if version == "" {
		return nil, fmt.Errorf("version: file is empty (expected semver like \"1.0.0\")")
	}
	mtimes["version"] = vmtime

	slow := &catalog.SlowData{
		Version:              version,
		FPBlocklist:          map[string]string{},
		IPBlocklist:          map[string]string{},
		UABlacklist:          []string{},
		IPWhitelist:          []string{},
		ASNDatacenters:       []uint32{},
		TLSFPCatalog:         map[string]catalog.TLSFPCatalog{},
		TLSFPBrowserProfiles: map[string]catalog.BrowserProfile{},
	}

	// tls_fp_blocklist: map(fp → status). Активные → fp: "block" в SlowData.
	// File-system имя файла — `tls_fp_blocklist.yaml` (имя из vision /
	// entities-reference.md). Внутреннее поле `SlowData.FPBlocklist` и
	// wire-endpoint `/catalog/fp_blocklist` оставлены historical (edge
	// shared_dict и модули зовут это `fp_blocklist`); расхождение задокументировано
	// в trackedFiles и catalogs/README.md.
	if mt, err := loadStatusMap(l.dir, "tls_fp_blocklist.yaml", func(active []string) error {
		for _, fp := range active {
			slow.FPBlocklist[fp] = "block"
		}
		return nil
	}); err != nil {
		return nil, err
	} else {
		mtimes["tls_fp_blocklist.yaml"] = mt
	}

	// ua_blacklist: map(pattern → status). Активные → []string в SlowData.
	if mt, err := loadStatusMap(l.dir, "ua_blacklist.yaml", func(active []string) error {
		slow.UABlacklist = append(slow.UABlacklist, active...)
		return nil
	}); err != nil {
		return nil, err
	} else {
		mtimes["ua_blacklist.yaml"] = mt
	}

	// ip_blocklist: map(cidr → status). Активные → cidr: "block".
	if mt, err := loadStatusMap(l.dir, "ip_blocklist.yaml", func(active []string) error {
		for _, cidr := range active {
			slow.IPBlocklist[cidr] = "block"
		}
		return nil
	}); err != nil {
		return nil, err
	} else {
		mtimes["ip_blocklist.yaml"] = mt
	}

	// ip_whitelist: top-level sequence of strings (без status).
	wl, mt, err := loadStringSlice(l.dir, "ip_whitelist.yaml")
	if err != nil {
		return nil, err
	}
	slow.IPWhitelist = wl
	mtimes["ip_whitelist.yaml"] = mt

	// asn_datacenters: top-level sequence of uint32 (без status).
	asns, mt, err := loadASNs(l.dir, "asn_datacenters.yaml")
	if err != nil {
		return nil, err
	}
	slow.ASNDatacenters = asns
	mtimes["asn_datacenters.yaml"] = mt

	// tls_fp_catalog: top-level map(hash_b → {family, status}). Validate
	// делает структурные проверки (непустой family, валидный status); сюда
	// просто кладём результат decodeYAML.
	tlsCat, mt, err := loadTLSFPCatalog(l.dir, "tls_fp_catalog.yaml")
	if err != nil {
		return nil, err
	}
	slow.TLSFPCatalog = tlsCat
	mtimes["tls_fp_catalog.yaml"] = mt

	// tls_fp_browser_profiles: top-level map(family → {expected_cipher_cnt, status}).
	tlsProf, mt, err := loadBrowserProfiles(l.dir, "tls_fp_browser_profiles.yaml")
	if err != nil {
		return nil, err
	}
	slow.TLSFPBrowserProfiles = tlsProf
	mtimes["tls_fp_browser_profiles.yaml"] = mt

	// Финальная валидация через catalog.Validate: regex компилируется,
	// CIDR парсятся как симметрично-к-ipmatcher'у. Та же модель, что в
	// dbloader.Load: упадём до того, как Store увидит битый payload.
	// Merge с nil runtime-частью — Validate проверит только slow-слой
	// (Policy пуст → per-host-валидация скипается).
	if err := catalog.Validate(catalog.Merge(slow, nil)); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	// Atomic apply кеша. До этой точки mtimes — локальная карта; чтобы
	// частичный fail (например, ip_whitelist прочли, asn упал) не сдвинул
	// l.mtimes — обновляем целиком на успехе.
	l.mtimes = mtimes
	return slow, nil
}

// readFile читает файл из dir и возвращает байты + mtime. Отсутствие
// файла — ошибка (защита от опечатки в имени; пустой каталог должен
// быть представлен пустым файлом / только комментариями).
func readFile(dir, name string) ([]byte, time.Time, error) {
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("stat %s: %w", name, err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // путь под контролем оператора, не из запроса
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read %s: %w", name, err)
	}
	return data, info.ModTime(), nil
}

// loadStatusMap читает YAML-файл вида map[string]string, валидирует
// status'ы, отдаёт активные ключи callback'у. Пустой файл / только
// комментарии → пустой active-список (это нормальное состояние «каталог
// ещё пуст»).
//
// Возвращает mtime файла, чтобы reloader мог его закешировать; ошибку —
// если YAML битый, ключ нестроковый, status незнакомый.
func loadStatusMap(dir, name string, apply func(active []string) error) (time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return time.Time{}, err
	}
	var m map[string]string
	if err := decodeYAML(data, &m, name); err != nil {
		return time.Time{}, err
	}
	active := make([]string, 0, len(m))
	for key, status := range m {
		if _, ok := validStatuses[status]; !ok {
			return time.Time{}, fmt.Errorf("%s: entry %q has invalid status %q (expected one of: active, staging)", name, key, status)
		}
		if status == statusActive {
			active = append(active, key)
		}
	}
	if err := apply(active); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", name, err)
	}
	return mt, nil
}

// loadStringSlice читает YAML-файл, top-level которого — последовательность
// строк. Пустой файл → пустой срез.
func loadStringSlice(dir, name string) ([]string, time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return nil, time.Time{}, err
	}
	var s []string
	if err := decodeYAML(data, &s, name); err != nil {
		return nil, time.Time{}, err
	}
	if s == nil {
		s = []string{}
	}
	return s, mt, nil
}

// loadTLSFPCatalog читает YAML-map(hash_b → {family, status}). Пустой файл /
// только комментарии = пустой каталог. Структурные проверки (непустой family,
// валидный status) делает catalog.Validate на следующем шаге Load.
func loadTLSFPCatalog(dir, name string) (map[string]catalog.TLSFPCatalog, time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return nil, time.Time{}, err
	}
	m := map[string]catalog.TLSFPCatalog{}
	if err := decodeYAML(data, &m, name); err != nil {
		return nil, time.Time{}, err
	}
	if m == nil {
		m = map[string]catalog.TLSFPCatalog{}
	}
	return m, mt, nil
}

// loadBrowserProfiles читает YAML-map(family → {expected_cipher_cnt, status}).
// Симметрично loadTLSFPCatalog: проверки в catalog.Validate.
func loadBrowserProfiles(dir, name string) (map[string]catalog.BrowserProfile, time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return nil, time.Time{}, err
	}
	m := map[string]catalog.BrowserProfile{}
	if err := decodeYAML(data, &m, name); err != nil {
		return nil, time.Time{}, err
	}
	if m == nil {
		m = map[string]catalog.BrowserProfile{}
	}
	return m, mt, nil
}

// loadASNs читает YAML-файл с последовательностью чисел и приводит к
// []uint32. Принимаем любое целое; границы 0..2^32-1 — потому что ASN
// 32-bit (RFC 6793). Отрицательное / больше uint32 — ошибка (как в
// dbloader.loadUint32List).
func loadASNs(dir, name string) ([]uint32, time.Time, error) {
	data, mt, err := readFile(dir, name)
	if err != nil {
		return nil, time.Time{}, err
	}
	var raw []int64
	if err := decodeYAML(data, &raw, name); err != nil {
		return nil, time.Time{}, err
	}
	out := make([]uint32, 0, len(raw))
	for _, n := range raw {
		if n < 0 || n > 0xFFFFFFFF {
			return nil, time.Time{}, fmt.Errorf("%s: ASN %d out of uint32 range", name, n)
		}
		out = append(out, uint32(n)) //nolint:gosec // G115: bounds checked above
	}
	return out, mt, nil
}

// decodeYAML — обёртка с strict mode (KnownFields(true)) и человекочитаемой
// ошибкой, в которой видно имя файла. Пустой документ (только комментарии /
// пробелы) даёт yaml.NewDecoder io.EOF — трактуем как «ничего не положили
// в dst», caller это поддерживает (nil-map / nil-slice).
func decodeYAML(data []byte, dst any, name string) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: yaml decode: %w", name, err)
	}
	return nil
}
