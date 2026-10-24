package allow

import (
	"regexp"
	"strings"
	"testing"
)

func TestKnownConstantsAreWellFormed(t *testing.T) {
	addr := regexp.MustCompile(`^[0-9a-f]{40}$`)
	word := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for v, name := range wellKnownConstants {
		if strings.HasPrefix(name, "secp256k1") {
			if !word.MatchString(v) {
				t.Errorf("%s: %q is not 64 hex digits", name, v)
			}
			continue
		}
		if !addr.MatchString(v) {
			t.Errorf("%s: %q is not a 20-byte address", name, v)
		}
	}
}

func TestKnownConstantIsCaseInsensitive(t *testing.T) {
	for _, v := range []string{
		"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
		"0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913",
		"833589fcd6edb6e08f4c7c32d4f71b54bda02913",
		"0x000000000000000000000000000000000000dEaD",
		"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
		"0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
	} {
		if _, ok := KnownConstant(v); !ok {
			t.Errorf("%q should be a known constant", v)
		}
	}
	if _, ok := KnownConstant("0x52908400098527886E0F7030069857D2E4169EE7"); ok {
		t.Error("an arbitrary address must not be a known constant")
	}
	if !Benign("wallet", "0x0000000000000000000000000000000000000000") || Benign("wallet", "0x52908400098527886E0F7030069857D2E4169EE7") {
		t.Error("Benign(wallet) must drop only known constants")
	}
}
