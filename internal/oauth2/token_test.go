package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseToken(t *testing.T) {
	for _, tc := range []struct {
		Name        string
		Req         func() *http.Request
		WantErr     bool
		WantErrCode TokenErrorCode
		Want        *TokenRequest
	}{
		{
			Name: "Bad method",
			Req: func() *http.Request {
				return httptest.NewRequest("HEAD", "/", nil)
			},
			WantErr: true,
		},
		{
			Name: "Good query",
			Req: queryReq(map[string]string{
				"code":          "acode",
				"redirect_uri":  "https://redirect",
				"client_id":     "client",
				"client_secret": "secret",
				"grant_type":    "authorization_code",
			}),
			Want: &TokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				Code:         "acode",
				RedirectURI:  "https://redirect",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		{
			Name: "Basic auth creds",
			Req: func() *http.Request {
				req := queryReq(map[string]string{
					"code":         "acode",
					"redirect_uri": "https://redirect",
					"grant_type":   "authorization_code",
				})()
				req.SetBasicAuth("clientuser", "clientsecret")
				return req
			},
			Want: &TokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				Code:         "acode",
				RedirectURI:  "https://redirect",
				ClientID:     "clientuser",
				ClientSecret: "clientsecret",
			},
		},
		{
			Name: "Invalid grant type",
			Req: queryReq(map[string]string{
				"code":          "acode",
				"redirect_uri":  "https://redirect",
				"client_id":     "client",
				"client_secret": "secret",
			}),
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidGrant,
		},
		{
			Name: "Valid refresh request succeeds",
			Req: queryReq(map[string]string{
				"grant_type":    "refresh_token",
				"refresh_token": "refreshtok",
				"client_id":     "client",
				"client_secret": "secret",
			}),
			Want: &TokenRequest{
				GrantType:    GrantTypeRefreshToken,
				RefreshToken: "refreshtok",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		{
			Name: "Refresh grant requires refresh token",
			Req: queryReq(map[string]string{
				"grant_type":    "refresh_token",
				"client_id":     "client",
				"client_secret": "secret",
			}),
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidRequest,
		},
		{
			Name: "Escaped basic auth creds", // https://tools.ietf.org/html/rfc6749#section-2.3.1
			Req: func() *http.Request {
				req := queryReq(map[string]string{
					"code":         "acode",
					"redirect_uri": "https://redirect",
					"grant_type":   "authorization_code",
				})()

				req.SetBasicAuth(url.QueryEscape("cl#i$nt"), url.QueryEscape("sec=ret%"))
				return req
			},
			Want: &TokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				Code:         "acode",
				RedirectURI:  "https://redirect",
				ClientID:     "cl#i$nt",
				ClientSecret: "sec=ret%",
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := ParseTokenRequest(tc.Req())
			if tc.WantErr && err == nil {
				t.Fatal("want err, got none")
			}
			if !tc.WantErr && err != nil {
				t.Fatalf("want no error, got: %v", err)
			}
			if tc.WantErrCode != TokenErrorCode("") {
				terr, ok := err.(*TokenError)
				if !ok {
					t.Fatalf("want tokenError, got: %v of type %T", err, err)
				}
				if tc.WantErrCode != terr.ErrorCode {
					t.Fatalf("want err code %s, got: %s", tc.WantErrCode, terr.ErrorCode)
				}
			}

			if diff := cmp.Diff(tc.Want, resp); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func queryReq(query map[string]string) func() *http.Request {
	f := url.Values{}
	for k, v := range query {
		f[k] = []string{v}
	}

	return func() *http.Request {
		req := httptest.NewRequest("POST", "https://token", strings.NewReader(f.Encode()))
		req.Header.Add("content-type", "application/x-www-form-urlencoded")
		return req
	}
}

func TestWriteTokenResponse(t *testing.T) {
	for _, tc := range []struct {
		Name string
		Resp *TokenResponse
		Want map[string]interface{}
	}{
		{
			Name: "valid response",
			Resp: &TokenResponse{
				AccessToken:  "access",
				TokenType:    "Bearer",
				ExpiresIn:    1 * time.Minute,
				RefreshToken: "refresh",
				Scopes:       []string{"openid"},
				ExtraParams: map[string]interface{}{
					"id_token": "beer",
				},
			},
			Want: map[string]interface{}{
				"access_token":  "access",
				"expires_in":    float64(60),
				"id_token":      "beer",
				"refresh_token": "refresh",
				"scope":         "openid",
				"token_type":    "Bearer",
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			w := httptest.NewRecorder()

			_ = WriteTokenResponse(w, tc.Resp)

			if w.Result().StatusCode != 200 {
				t.Errorf("want OK status, got %d", w.Result().StatusCode)
			}

			got := map[string]interface{}{}
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.Want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}
