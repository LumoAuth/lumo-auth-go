package lumoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

// net/http helper for the Personal Agent Protocol: middleware that verifies
// the request of a personal agent before the handler runs.

// PoppyMiddlewareOptions configures PoppyResource.Middleware.
type PoppyMiddlewareOptions struct {
	// PublicOrigin is the address that personal agents call, for example
	// "https://shop.example.com". It may carry a base path. Take it from
	// your configuration. Required.
	PublicOrigin string
	// RequiredScope lists the scopes that the routes behind this
	// middleware need. Leave it empty for routes that work signed out.
	RequiredScope []string
	// Resource is the resource identifier of your service, when it takes
	// only access tokens that were issued for it.
	Resource string
	// AllowReplay accepts a Session JWT that was verified before.
	AllowReplay bool
	// OnError is called when the verification call itself fails: the SDK
	// could not reach LumoAuth, or LumoAuth refused your application's call
	// (for example 404 not_found while the organization has the protocol
	// switched off: errors.Is(err, ErrNotFound)). It must answer the
	// request. Never write err to the response: it is about your service,
	// not about the personal agent. When OnError is nil, the middleware
	// answers 503 with the fixed body {"error":"temporarily_unavailable",…}.
	// The SDK does not log, so set OnError to record the error.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

// Middleware returns net/http middleware that verifies each request with
// LumoAuth before the handler runs.
//
//	verified, err := client.Poppy.Middleware(lumoauth.PoppyMiddlewareOptions{
//	    PublicOrigin:  "https://shop.example.com",
//	    RequiredScope: []string{"orders:read"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	mux.Handle("GET /api/orders", verified(ordersHandler))
//
//	// in ordersHandler:
//	who, _ := lumoauth.PoppyFromContext(r.Context())
//
// For each request the middleware does one of three things:
//
//   - Verified: it stores the *PoppyVerification in the request context and
//     calls the handler.
//   - Refused: it answers with LumoAuth's response, unchanged, and does not
//     call the handler.
//   - The call failed: it does not call the handler and relays nothing. It
//     calls OnError, or answers 503 Service Unavailable with a fixed body.
//     The error text never reaches the personal agent.
//
// The URL that LumoAuth checks is PublicOrigin followed by the path of
// r.RequestURI. The Host and X-Forwarded-* headers are never used. Because
// r.RequestURI is the request line as the client sent it, a router prefix
// or http.StripPrefix in front of the middleware does not shorten the path.
// The middleware does not read the request body.
//
// A Session JWT is good for one verification, so put the middleware on a
// route once.
//
// Middleware returns a *ConfigError when PublicOrigin is missing or is not
// a valid address, when the client has no client credentials
// (WithClientCredentials) or when it has neither an organization ID nor a
// custom domain.
func (r *PoppyResource) Middleware(opts PoppyMiddlewareOptions) (func(http.Handler) http.Handler, error) {
	origin, err := poppyPublicOrigin(opts.PublicOrigin)
	if err != nil {
		return nil, err
	}
	if _, err := r.credentials(); err != nil {
		return nil, err
	}
	if _, _, err := r.http.resolve(RoutePoppyVerifyRequest, nil); err != nil {
		return nil, err
	}
	verifyOpts := &PoppyVerifyOptions{
		RequiredScope: append([]string(nil), opts.RequiredScope...),
		Resource:      opts.Resource,
		AllowReplay:   opts.AllowReplay,
	}
	fail := opts.OnError
	if fail == nil {
		fail = writePoppyFailure
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			verification, err := r.VerifyHTTPRequest(req.Context(), origin, req, verifyOpts)
			if err != nil {
				fail(w, req, err)
				return
			}
			if !verification.Active {
				refusal, err := newPoppyRefusal(verification)
				if err != nil {
					fail(w, req, err)
					return
				}
				_ = refusal.write(w)
				return
			}
			next.ServeHTTP(w, req.WithContext(ContextWithPoppy(req.Context(), verification)))
		})
	}, nil
}

// poppyUnavailableBody is the answer for a failed verification call when no
// OnError is set. It says nothing about the cause, which concerns this
// service and not the personal agent.
const poppyUnavailableBody = `{"error":"temporarily_unavailable","error_description":"Requests from personal agents cannot be verified right now."}`

// writePoppyFailure answers a failed verification call when no OnError is
// set: 503, because the service cannot verify the request now (the
// protocol is switched off, the application's credential is refused,
// LumoAuth is out of reach). It is never a 500, and never a refusal of the
// personal agent's own credentials.
func writePoppyFailure(w http.ResponseWriter, _ *http.Request, _ error) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(poppyUnavailableBody))
}

type poppyContextKey struct{}

// PoppyFromContext returns the verified result that PoppyResource.Middleware
// stored for the request.
func PoppyFromContext(ctx context.Context) (*PoppyVerification, bool) {
	verification, ok := ctx.Value(poppyContextKey{}).(*PoppyVerification)
	return verification, ok && verification != nil
}

// ContextWithPoppy stores a verified result in a context, for handlers that
// call VerifyRequest themselves but share downstream code with Middleware.
func ContextWithPoppy(ctx context.Context, verification *PoppyVerification) context.Context {
	return context.WithValue(ctx, poppyContextKey{}, verification)
}

// WritePoppyRefusal sends a refusal to the personal agent as LumoAuth
// worded it: the status, every header and the body of
// verification.Response. A body is sent as JSON with Content-Type
// application/json. A response without a body gets no body and no
// Content-Type. Nothing else is added.
//
//	if !verification.Active {
//	    lumoauth.WritePoppyRefusal(w, verification)
//	    return
//	}
//
// It returns a *ValidationError, and writes nothing, when verification is
// not a refusal. Otherwise it returns the error of the write, if any.
func WritePoppyRefusal(w http.ResponseWriter, verification *PoppyVerification) error {
	refusal, err := newPoppyRefusal(verification)
	if err != nil {
		return err
	}
	return refusal.write(w)
}

// poppyRefusal is a refusal that is ready to write.
type poppyRefusal struct {
	status  int
	headers map[string]string
	body    []byte // nil when the response has no body
}

func newPoppyRefusal(verification *PoppyVerification) (*poppyRefusal, error) {
	if verification == nil || verification.Active || verification.Response == nil {
		return nil, NewValidationError("there is no refusal to send: the verification is not a refusal with a response")
	}
	response := verification.Response
	if response.Status < 400 || response.Status > 599 {
		return nil, validationErrorf("the refusal has the status %d, which is not an HTTP error status", response.Status)
	}
	refusal := &poppyRefusal{status: response.Status, headers: response.Headers}
	if response.Body != nil {
		// No HTML escaping: the body is JSON for a personal agent, and
		// "<" in a description must arrive as LumoAuth wrote it.
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(response.Body); err != nil {
			return nil, validationErrorf("could not encode the body of the refusal: %v", err)
		}
		refusal.body = bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
	}
	return refusal, nil
}

func (p *poppyRefusal) write(w http.ResponseWriter) error {
	header := w.Header()
	for name, value := range p.headers {
		header.Set(name, value)
	}
	if p.body == nil {
		w.WriteHeader(p.status)
		return nil
	}
	header.Set("Content-Type", "application/json")
	w.WriteHeader(p.status)
	_, err := w.Write(p.body)
	return err
}
