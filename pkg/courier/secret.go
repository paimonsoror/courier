package courier

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
)

const redacted = "[REDACTED]"

// Secret holds a credential value. Every formatting, logging and JSON path
// prints [REDACTED]; only Reveal returns the value.
type Secret struct {
	value string
}

// NewSecret wraps a credential value.
func NewSecret(v string) Secret { return Secret{value: v} }

// GenerateSecret returns a 64-character URL-safe random secret (384 bits).
func GenerateSecret() (Secret, error) {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return Secret{}, err
	}
	return Secret{value: base64.RawURLEncoding.EncodeToString(b)}, nil
}

// Reveal returns the raw value. Call it only at the point of handing the
// secret to an IdP or secret store API.
func (s Secret) Reveal() string { return s.value }

// IsZero reports whether no value is set.
func (s Secret) IsZero() bool { return s.value == "" }

func (s Secret) String() string                { return redacted }
func (s Secret) GoString() string              { return redacted }
func (s Secret) LogValue() slog.Value          { return slog.StringValue(redacted) }
func (s Secret) MarshalJSON() ([]byte, error)  { return []byte(`"` + redacted + `"`), nil }
func (s Secret) MarshalText() ([]byte, error)  { return []byte(redacted), nil }
