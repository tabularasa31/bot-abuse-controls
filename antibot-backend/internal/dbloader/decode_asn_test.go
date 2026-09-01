// An internal test (same package) for decodeASNBlock — it is unexported
// and must stay that way: it is called only from loadPolicy.
//
// The coverage per review: out-of-range elements (negative,
// >2^32-1) are skipped WITHOUT an error, so that one broken ASN does not fail the whole
// catalog tick → an edge fail-stale for the entire pool.
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
		// Out-of-range elements are skipped and valid ones are kept.
		{"negative skipped", "[-1, 100, -5, 200]", []uint32{100, 200}, false},
		{"too big skipped", "[5000000000, 100]", []uint32{100}, false},
		{"all out of range", "[-1, 5000000000]", []uint32{}, false},
		// A JSON null: we do NOT map it to 0 (the default-zero trap).
		{"single null skipped", "[null]", []uint32{}, false},
		{"null mixed with valid", "[null, 100, null, 200]", []uint32{100, 200}, false},
		// Broken JSON → an error (that is no longer "one broken element", it is a broken
		// field — the loader must fail stale rather than silently skip it).
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

// TestDecodeASNBlock_EmptyResetsDst pins the contract that an empty input
// yields a nil output, which must hold even for a caller that reuses dst.
// The function used to leave dst untouched on an empty input → a future refactor
// reusing a Policy struct would silently leak a stale ASN.
func TestDecodeASNBlock_EmptyResetsDst(t *testing.T) {
	dst := []uint32{1, 2, 3}
	if err := decodeASNBlock(nil, &dst); err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if dst != nil {
		t.Errorf("empty input did not reset dst: got %v, want nil", dst)
	}
}
