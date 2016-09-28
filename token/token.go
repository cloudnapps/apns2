package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	// TokenTimeout is the period of time in seconds that a token is valid for.
	// If the timestamp for token issue is not within the last hour, APNs
	// rejects subsequent push messages. This is set to under an hour so that
	// we generate a new token before the existing one expires.
	TokenTimeout = 3000
)

// Possible errors when parsing a .p8 file.
var (
	ErrAuthKeyWrongType = errors.New("token: AuthKey must be of type ecdsa.PrivateKey")
)

// Token represents an Apple Provider Authentication Token (JSON Web Token).
type Token struct {
	AuthKey  *ecdsa.PrivateKey
	KeyID    string
	TeamID   string
	IssuedAt int64
	Bearer   string
	m        sync.Mutex
}

// AuthKeyFromFile loads a .p8 certificate from a local file and returns a
// *ecdsa.PrivateKey.
func AuthKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return AuthKeyFromBytes(bytes)
}

// AuthKeyFromBytes loads a .p8 certificate from an in memory byte array and
// returns an *ecdsa.PrivateKey.
func AuthKeyFromBytes(bytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pk := key.(type) {
	case *ecdsa.PrivateKey:
		return pk, nil
	default:
		return nil, ErrAuthKeyWrongType
	}
}

// GenerateIfExpired checks to see if the token is about to expire and
// generates a new token.
func (t *Token) GenerateIfExpired() {
	t.m.Lock()
	defer t.m.Unlock()
	if t.Expired() {
		t.Generate()
	}
}

// Expired checks to see if the token has expired.
func (t *Token) Expired() bool {
	return time.Now().Unix() >= (t.IssuedAt + TokenTimeout)
}

// Generate creates a new token.
func (t *Token) Generate() (bool, error) {
	issuedAt := time.Now().Unix()
	jwtToken := &jwt.Token{
		Header: map[string]interface{}{
			"alg": "ES256",
			"kid": t.KeyID,
		},
		Claims: jwt.MapClaims{
			"iss": t.TeamID,
			"iat": issuedAt,
		},
		Method: jwt.SigningMethodES256,
	}
	bearer, err := jwtToken.SignedString(t.AuthKey)
	if err != nil {
		return false, err
	}
	t.IssuedAt = issuedAt
	t.Bearer = bearer
	return true, nil
}
