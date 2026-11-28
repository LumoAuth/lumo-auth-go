package lumoauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// The default session store of WebAuth: the session lives in the browser,
// encrypted (AES-256) and signed (HMAC-SHA256) by gorilla/securecookie, with
// both keys derived from WebConfig.SessionSecret. A session with the tokens of
// the default scopes is larger than the 4096 bytes that a browser keeps per
// cookie, so the encoded value is split: the first part goes in the cookie
// named CookieName, the next ones in CookieName.1, CookieName.2, and so on.

const (
	// sessionChunkSize is the largest value of one cookie. Together with the
	// name and the attributes it stays below the 4096 bytes that browsers
	// keep per cookie.
	sessionChunkSize = 3800
	// sessionMaxChunks bounds the cookies of one session. Eight full chunks
	// are a Cookie header of about 30 KB, more than many proxies accept, so a
	// larger session needs a server-side store (WebConfig.Store).
	sessionMaxChunks = 8
)

// Labels of the keys derived from the session secret. Changing one ends every
// session.
const (
	sessionMACKeyLabel        = "lumoauth-go web session: signing key"
	sessionEncryptionKeyLabel = "lumoauth-go web session: encryption key"
)

// chunkedCookieStore is a sessions.Store that keeps the session in one or
// more encrypted cookies.
type chunkedCookieStore struct {
	codecs  []securecookie.Codec
	options *sessions.Options
}

// newChunkedCookieStore builds the store for a session secret. The first
// codec encrypts and signs. The second one only reads: it accepts the
// signed, unencrypted cookie that earlier versions of this SDK wrote with the
// same secret, so that an upgrade ends no session. Every save writes the
// encrypted form.
func newChunkedCookieStore(secret string, options *sessions.Options) *chunkedCookieStore {
	current := securecookie.New(
		deriveSessionKey(secret, sessionMACKeyLabel),
		deriveSessionKey(secret, sessionEncryptionKeyLabel),
	)
	legacy := securecookie.New([]byte(secret), nil)

	store := &chunkedCookieStore{
		codecs:  []securecookie.Codec{current, legacy},
		options: options,
	}
	for _, codec := range []*securecookie.SecureCookie{current, legacy} {
		// The store splits long values itself; the codec must not refuse
		// them. MaxAge bounds the age of a cookie's timestamp as well as the
		// cookie's lifetime.
		codec.MaxLength(0)
		codec.MaxAge(options.MaxAge)
	}
	return store
}

// deriveSessionKey derives a 32-byte key from the session secret, one per
// purpose, so the signing key and the encryption key are never the same.
func deriveSessionKey(secret, label string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// Get returns the request's session, decoded once per request.
func (s *chunkedCookieStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New decodes the session from the request's cookies. A missing, forged or
// expired session gives a new, empty session; for the last two the error says
// why.
func (s *chunkedCookieStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	options := *s.options
	session.Options = &options
	session.IsNew = true

	encoded, ok := readSessionChunks(r, name)
	if !ok {
		return session, nil
	}
	if err := securecookie.DecodeMulti(name, encoded, &session.Values, s.codecs...); err != nil {
		session.Values = map[interface{}]interface{}{}
		return session, err
	}
	session.IsNew = false
	return session, nil
}

// Save writes the session, split over as many cookies as it needs, and
// expires the chunks of an earlier, larger session. A session whose
// Options.MaxAge is negative is removed: every one of its cookies expires.
func (s *chunkedCookieStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	options := session.Options
	if options == nil {
		copied := *s.options
		options = &copied
	}
	name := session.Name()

	var chunks []string
	if options.MaxAge >= 0 {
		encoded, err := securecookie.EncodeMulti(name, session.Values, s.codecs...)
		if err != nil {
			return err
		}
		chunks = splitSessionValue(encoded)
		if len(chunks) > sessionMaxChunks {
			return NewConfigError(fmt.Sprintf(
				"the session is %d bytes, too large for cookies: use WebConfig.Store with a server-side session store, or request fewer scopes",
				len(encoded)))
		}
	}

	for i, chunk := range chunks {
		http.SetCookie(w, sessions.NewCookie(sessionChunkName(name, i), chunk, options))
	}

	// Expire what the browser still holds beyond the new session: the
	// chunks of an earlier, larger session, or everything on removal.
	expired := *options
	expired.MaxAge = -1
	if len(chunks) == 0 {
		http.SetCookie(w, sessions.NewCookie(name, "", &expired))
	}
	for i := max(len(chunks), 1); i < sessionMaxChunks; i++ {
		if _, err := r.Cookie(sessionChunkName(name, i)); err != nil {
			continue
		}
		http.SetCookie(w, sessions.NewCookie(sessionChunkName(name, i), "", &expired))
	}
	return nil
}

// sessionChunkName is the cookie name of chunk i: the session name for the
// first chunk, then name.1, name.2, ….
func sessionChunkName(name string, i int) string {
	if i == 0 {
		return name
	}
	return name + "." + strconv.Itoa(i)
}

// splitSessionValue cuts an encoded session into cookie-sized chunks.
func splitSessionValue(encoded string) []string {
	chunks := make([]string, 0, len(encoded)/sessionChunkSize+1)
	for len(encoded) > sessionChunkSize {
		chunks = append(chunks, encoded[:sessionChunkSize])
		encoded = encoded[sessionChunkSize:]
	}
	return append(chunks, encoded)
}

// readSessionChunks joins the session's cookies in order: the cookie named
// name, then name.1, name.2, … up to the first one that is missing. Chunks
// that do not belong together fail the signature check when decoded.
func readSessionChunks(r *http.Request, name string) (string, bool) {
	first, err := r.Cookie(name)
	if err != nil || first.Value == "" {
		return "", false
	}
	var joined strings.Builder
	joined.WriteString(first.Value)
	for i := 1; i < sessionMaxChunks; i++ {
		chunk, err := r.Cookie(sessionChunkName(name, i))
		if err != nil {
			break
		}
		joined.WriteString(chunk.Value)
	}
	return joined.String(), true
}
