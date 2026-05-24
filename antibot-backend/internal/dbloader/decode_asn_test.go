// Internal test (same package) для decodeASNBlock — он unexported
// и не должен экспортироваться: вызывается только из loadPolicy.
//
// Покрытие per PR-58 review #6: out-of-range элементы (отрицательные,
// >2^32-1) скипаются БЕЗ ошибки, чтобы один битый ASN не валил весь
// catalog-тик → edge fail-stale для всего пула.
package dbloader

import (
	"reflect"
	"testing"
)

func TestDecodeASNBlock(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []uint32
		wantErr bool
	}{
		{"empty bytes", "", nil, false},
		{"empty array", "[]", []uint32{}, false},
		{"valid", "[15169, 13335, 1]", []uint32{15169, 13335, 1}, false},
		{"with zero", "[0, 1]", []uint32{0, 1}, false},
		{"max uint32", "[4294967295]", []uint32{4294967295}, false},
		// Out-of-range элементы скипаются, валидные сохраняются.
		{"negative skipped", "[-1, 100, -5, 200]", []uint32{100, 200}, false},
		{"too big skipped", "[5000000000, 100]", []uint32{100}, false},
		{"all out of range", "[-1, 5000000000]", []uint32{}, false},
		// JSON null: НЕ маппим в 0 (default-zero ловушка). PR-58 review #2.
		{"single null skipped", "[null]", []uint32{}, false},
		{"null mixed with valid", "[null, 100, null, 200]", []uint32{100, 200}, false},
		// Битый JSON → ошибка (это уже не «один битый элемент», это поломанное
		// поле — loader должен fail-stale, а не серебряно скипнуть).
		{"bad json", "not-json", nil, true},
		{"not array", `{"x":1}`, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []uint32
			err := decodeASNBlock([]byte(tc.in), &got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDecodeASNBlock_EmptyResetsDst — PR-58 review #6: contract «empty
// input → nil output» должен держаться даже при reuse'aющем caller'е.
// Раньше функция оставляла dst untouched на empty input → future-refactor
// с переиспользованием Policy struct silently leak'ал stale ASN.
func TestDecodeASNBlock_EmptyResetsDst(t *testing.T) {
	dst := []uint32{1, 2, 3}
	if err := decodeASNBlock(nil, &dst); err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if dst != nil {
		t.Errorf("empty input did not reset dst: got %v, want nil", dst)
	}
}
