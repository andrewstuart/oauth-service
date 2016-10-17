package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/rs/cors"
)

//OAuthMux abstracts AuthN for an underlying mux
type OAuthMux struct {
	m http.Handler
	c http.Client

	Base string

	ClientID, ClientPass string
}

func (m *OAuthMux) format(endpoint string, params map[string]string) string {
	s := fmt.Sprintf("%s/%s?client_id=%s&client_secret=%s&", m.Base, endpoint, m.ClientID, m.ClientPass)

	a := []string{}
	for k, v := range params {
		a = append(a, fmt.Sprintf("%s=%s", k, v))
	}
	return s + strings.Join(a, "&")
}

func (m *OAuthMux) getToken(code string) (string, error) {
	s := m.format("token", map[string]string{
		"grant_type": "authorization_code",
		"code":       code,
	})

	log.Println(s)

	res, err := m.c.Get(s)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var resm structRes
	err = json.NewDecoder(io.TeeReader(res.Body, os.Stderr)).Decode(&resm)
	if err != nil {
		return "", err
	}

	return resm.AccessToken, err
}

type structRes struct {
	AccessToken string `json:"access_token"`
}

//ServeHTTP
func (m *OAuthMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var token string
	var err error

	hdr, code := r.Header.Get("Authorization"), r.URL.Query().Get("code")
	switch {
	case code != "":
		token, err = m.getToken(code)
		if err != nil {
			log.Println("Error getting token", err)
			http.Error(w, "Invalid auth code", 401)
			return
		}
	case hdr != "" && !strings.HasPrefix(hdr, "Bearer "):
		token = strings.TrimPrefix(hdr, "Bearer ")
	default:
		url := m.format("authorize", map[string]string{
			"response_type": "code",
		})
		http.Redirect(w, r, url, 302)
		return
	}

	log.Println("Bearer token: ", token)

	req, err := http.NewRequest("GET", m.Base+"/userinfo", nil)
	if err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := m.c.Do(req)
	if err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}

	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		log.Println("Non-200 userinfo response:")
		res.Write(os.Stderr)
		w.WriteHeader(403)
		return
	}

	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "Problem getting userinfo", 403)
		return
	}

	userInfo[r] = bs

	// Pass through
	m.m.ServeHTTP(w, r)

	delete(userInfo, r)
}

//NewOAuthMux accepts a mux and some details, and returns an oauth mux instance
func NewOAuthMux(sub http.Handler, base, cid, cpass string) *OAuthMux {
	m := OAuthMux{
		m:          sub,
		Base:       base,
		ClientID:   cid,
		ClientPass: cpass,
	}

	t := &tls.Config{
		RootCAs: x509.NewCertPool(),
	}

	t.RootCAs.AppendCertsFromPEM([]byte(os.Getenv("ROOT_CA")))

	tr := &http.Transport{
		TLSClientConfig: t,
	}

	m.c = http.Client{Transport: tr}

	return &m
}

func handleReq(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`This is a secret: "Hello"`))
	if userInfo[r] != nil {
		w.Write(userInfo[r])
	}
}

var (
	oauthServer                      = os.Getenv("OAUTH_SERVER")
	oauthClientID, oauthClientSecret = os.Getenv("OAUTH_CLIENT_ID"), os.Getenv("OAUTH_CLIENT_SECRET")

	userInfo = make(map[*http.Request][]byte)
)

func main() {
	m := http.NewServeMux()

	m.HandleFunc("/", handleReq)
	om := NewOAuthMux(m, oauthServer, oauthClientID, oauthClientSecret)

	opt := cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "PUT", "POST", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Accept"},
		Debug:          true,
	}

	handler := cors.New(opt).Handler(om)

	log.Fatal(http.ListenAndServe(":8080", handler))
}
