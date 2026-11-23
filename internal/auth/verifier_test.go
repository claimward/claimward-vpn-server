package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func signRS256(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + enc.EncodeToString(sig)
}

func domainVerifier(t *testing.T, key *rsa.PrivateKey) *OIDCVerifier {
	t.Helper()
	return &OIDCVerifier{
		verifier:       oidc.NewVerifier("https://idp.example", &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.Public()}}, &oidc.Config{ClientID: "claimward"}),
		allowedDomains: []string{"corp.example"},
	}
}

func idToken(t *testing.T, key *rsa.PrivateKey, email string, verified bool) string {
	return signRS256(t, key, map[string]any{
		"iss": "https://idp.example", "aud": "claimward", "sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": email, "email_verified": verified,
	})
}

// OIDC_ALLOWED_DOMAINS must not accept an address the IdP did not verify.
func TestOIDCDomainAllowlistNeedsVerifiedEmail(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := domainVerifier(t, key)
	if c, err := v.Verify(context.Background(), idToken(t, key, "ceo@corp.example", false)); err == nil {
		t.Errorf("unverified email passed the domain allowlist: %+v", c)
	}
	if _, err := v.Verify(context.Background(), idToken(t, key, "ceo@corp.example", true)); err != nil {
		t.Errorf("verified email in an allowed domain refused: %v", err)
	}
	if _, err := v.Verify(context.Background(), idToken(t, key, "x@evil.example", true)); err == nil {
		t.Error("verified email in another domain accepted")
	}
}
