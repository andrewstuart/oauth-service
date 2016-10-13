package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
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

//ServeHTTP
func (m *OAuthMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdr := r.Header.Get("Authorization")

	if hdr == "" || !strings.HasPrefix(hdr, "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Redirect(w, r, fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&client_secret=%s&scope=openid profile", m.Base, m.ClientID, m.ClientPass), 302)
		return
	}

	token := strings.TrimPrefix(hdr, "Bearer ")

	r, err := http.NewRequest("GET", m.Base+"/userinfo?token="+token, nil)
	if err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := m.c.Do(r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(403)
		return
	}

	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		log.Println("Non-200 userinfo response")
		w.WriteHeader(403)
		return
	}

	log.Println("Body")
	io.Copy(os.Stdout, res.Body)
	log.Println()

	// Pass through
	m.m.ServeHTTP(w, r)
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

	t.RootCAs.AppendCertsFromPEM([]byte(`-----BEGIN CERTIFICATE-----
MIIFBjCCA+6gAwIBAgIJAK8VTiAkL3fOMA0GCSqGSIb3DQEBCwUAMIGyMQswCQYD
VQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTEQMA4GA1UEBxMHUGhvZW5peDEbMBkG
A1UEChMSQW5kcmV3IFN0dWFydCBIb21lMR4wHAYDVQQDExVBbmRyZXcgU3R1YXJ0
IEhvbWUgQ0ExGTAXBgNVBCkTEEFuZHJldyBTdHVhcnQgQ0ExJzAlBgkqhkiG9w0B
CQEWGGFuZHJldy5zdHVhcnQyQGdtYWlsLmNvbTAeFw0xNDA5MDMyMjE5NTRaFw0y
NDA4MzEyMjE5NTRaMIGyMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTEQ
MA4GA1UEBxMHUGhvZW5peDEbMBkGA1UEChMSQW5kcmV3IFN0dWFydCBIb21lMR4w
HAYDVQQDExVBbmRyZXcgU3R1YXJ0IEhvbWUgQ0ExGTAXBgNVBCkTEEFuZHJldyBT
dHVhcnQgQ0ExJzAlBgkqhkiG9w0BCQEWGGFuZHJldy5zdHVhcnQyQGdtYWlsLmNv
bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK6ykSmw2Wz044FKHrA4
JmQeqUmexK9LaMpE582zYI/FJKiLcqkmAWdh6a5uXxhEYHd2sI8YDtOxspGvgFr6
+/wMhNj/PPNauODtuHOpb/r4aICQIzYjGSqXJmdf2RspuoCQ6Pe+4IXbwoPYqMt0
MlmDkZE83koIYRQwDWCCyG+6OmboupYk1t5cGoyHaRDg8jho0dz2rNK/xi7+HfyJ
UGPtAdnR3Qltxr72jOe2xZa0AOLKOgm1vjGkpOdObOPzl2Hl38KdyiJReYZwl/GZ
EJdeJ2vPiw/yedfsvZRG/GEBhA+arCfCjtT/MOMfP1CtSgySYk3kxuqnl4AsJSsV
INUCAwEAAaOCARswggEXMB0GA1UdDgQWBBTb8lmd/8QXS23rvr8PK5QJJQD3mDCB
5wYDVR0jBIHfMIHcgBTb8lmd/8QXS23rvr8PK5QJJQD3mKGBuKSBtTCBsjELMAkG
A1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEDAOBgNVBAcTB1Bob2VuaXgxGzAZ
BgNVBAoTEkFuZHJldyBTdHVhcnQgSG9tZTEeMBwGA1UEAxMVQW5kcmV3IFN0dWFy
dCBIb21lIENBMRkwFwYDVQQpExBBbmRyZXcgU3R1YXJ0IENBMScwJQYJKoZIhvcN
AQkBFhhhbmRyZXcuc3R1YXJ0MkBnbWFpbC5jb22CCQCvFU4gJC93zjAMBgNVHRME
BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB/GtftqidPdGtfwe/CRgc87ruo0Iji
4CQVJI+XoJnwE2yuLgD2M8vcjw9fWrKQ7J1mA+WHKoCB4QMDkEytEL5nxzWw6yeL
r4hNZNpx8CNNhbcFHpwHEPiduymnPYBGPSF4GNFNDd3cyGaKVjaekNCr9USVcLJM
X6IdY6671Q6Y6PXc849mBfHRVVGE2E/hhYFedmzEjR2VMTMcKbS5VxSdGHL2azH/
J+gVWvm63i6pW17ka7xwr7afsplSZym9+lfzdXd+OdUvIiHvwzQXh88Ti9pXIMkP
EtgPToljjjyaj9RwMaoQnlBPNTg5ynDCvf+V7FghdBYicyJ0EbByoNI6
-----END CERTIFICATE-----`))

	tr := &http.Transport{
		TLSClientConfig: t,
	}

	m.c = http.Client{Transport: tr}

	return &m
}

func handleReq(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`This is a secret: "Hello"`))
}

var (
	oauthServer                      = os.Getenv("OAUTH_SERVER")
	oauthClientID, oauthClientSecret = os.Getenv("OAUTH_CLIENT_ID"), os.Getenv("OAUTH_CLIENT_SECRET")
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
