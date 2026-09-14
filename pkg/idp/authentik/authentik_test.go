package authentik

import "testing"

func TestDiffers(t *testing.T) {
	current := map[string]any{
		"name":        "courier-team-alpha-orders-portal",
		"provider":    float64(12),
		"grant_types": []any{"refresh_token", "authorization_code"},
		"redirect_uris": []any{
			map[string]any{"url": "https://b.example/cb", "matching_mode": "strict"},
			map[string]any{"matching_mode": "strict", "url": "https://a.example/cb"},
		},
		"client_secret": "never compared",
	}

	same := map[string]any{
		"name":        "courier-team-alpha-orders-portal",
		"provider":    12,
		"grant_types": []string{"authorization_code", "refresh_token"},
		"redirect_uris": []map[string]string{
			{"matching_mode": "strict", "url": "https://a.example/cb"},
			{"matching_mode": "strict", "url": "https://b.example/cb"},
		},
	}
	if differs(same, current) {
		t.Fatal("identical settings in a different order or numeric type must not count as drift")
	}

	for name, want := range map[string]map[string]any{
		"grant removed":   {"grant_types": []string{"authorization_code"}},
		"redirect edited": {"redirect_uris": []map[string]string{{"matching_mode": "strict", "url": "https://c.example/cb"}}},
		"field missing":   {"include_claims_in_id_token": true},
		"value changed":   {"provider": 13},
	} {
		if !differs(want, current) {
			t.Fatalf("%s: drift not detected", name)
		}
	}
}
