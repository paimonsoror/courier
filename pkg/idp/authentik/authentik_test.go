package authentik

import "testing"

const (
	keyProvider     = "provider"
	keyGrantTypes   = "grant_types"
	keyRedirectURIs = "redirect_uris"
	keyMatchingMode = "matching_mode"
	keyURL          = "url"
	grantAuthCode   = "authorization_code"
	grantRefresh    = "refresh_token"
	strict          = "strict"
	redirectA       = "https://a.example/cb"
	redirectB       = "https://b.example/cb"
)

func TestDiffers(t *testing.T) {
	current := map[string]any{
		"name":      "courier-team-alpha-orders-portal",
		keyProvider: float64(12),
		keyGrantTypes: []any{grantRefresh, grantAuthCode},
		keyRedirectURIs: []any{
			map[string]any{keyURL: redirectB, keyMatchingMode: strict},
			map[string]any{keyMatchingMode: strict, keyURL: redirectA},
		},
		"client_secret": "never compared",
	}

	same := map[string]any{
		"name":        "courier-team-alpha-orders-portal",
		keyProvider:   12,
		keyGrantTypes: []string{grantAuthCode, grantRefresh},
		keyRedirectURIs: []map[string]string{
			{keyMatchingMode: strict, keyURL: redirectA},
			{keyMatchingMode: strict, keyURL: redirectB},
		},
	}
	if differs(same, current) {
		t.Fatal("identical settings in a different order or numeric type must not count as drift")
	}

	for name, want := range map[string]map[string]any{
		"grant removed":   {keyGrantTypes: []string{grantAuthCode}},
		"redirect edited": {keyRedirectURIs: []map[string]string{{keyMatchingMode: strict, keyURL: "https://c.example/cb"}}},
		"field missing":   {"include_claims_in_id_token": true},
		"value changed":   {keyProvider: 13},
	} {
		if !differs(want, current) {
			t.Fatalf("%s: drift not detected", name)
		}
	}
}
