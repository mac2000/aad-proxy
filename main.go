package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

//go:embed resources
var resources embed.FS

//go:embed templates
var templates embed.FS

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	homeTemplate, err := template.ParseFS(templates, "templates/index.tmpl")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse home page template")
	}
	errorTemplate, err := template.ParseFS(templates, "templates/error.tmpl")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse error page template")
	}

	ctx := context.Background()

	tenantID := os.Getenv("AAD_TENANT_ID")
	clientId := os.Getenv("AAD_CLIENT_ID")
	clientSecret := os.Getenv("AAD_CLIEN_SECRET")
	callbackURL := os.Getenv("AAD_CALLBACK_URL")
	cookieDomain := os.Getenv("AAD_COOKIE_DOMAIN")
	cookieName := os.Getenv("AAD_COOKIE_NAME")

	headerId := os.Getenv("AAD_HEADER_ID")
	if headerId == "" {
		headerId = "X-AAD-ID"
	}
	headerName := os.Getenv("AAD_HEADER_NAME")
	if headerName == "" {
		headerName = "X-AAD-NAME"
	}
	headerUsername := os.Getenv("AAD_HEADER_USERNAME")
	if headerUsername == "" {
		headerUsername = "X-AAD-USERNAME"
	}
	headerEmail := os.Getenv("AAD_HEADER_EMAIL")
	if headerEmail == "" {
		headerEmail = "X-AAD-EMAIL"
	}
	headerRoles := os.Getenv("AAD_HEADER_ROLES")
	if headerRoles == "" {
		headerRoles = "X-AAD-ROLES"
	}

	headerRole := os.Getenv("AAD_HEADER_ROLE")
	if headerRole == "" {
		headerRole = "X-AAD-ROLE"
	}
	headerRoleMap := os.Getenv("AAD_HEADER_ROLE_MAP")
	keys := []string{}
	vals := []string{}
	if headerRoleMap != "" {
		for _, kvp := range strings.Split(headerRoleMap, ",") {
			kvp = strings.Trim(kvp, " ")
			kv := strings.Split(kvp, ":")
			key := strings.Trim(kv[0], " ")
			val := strings.Trim(kv[1], " ")
			keys = append(keys, key)
			vals = append(vals, val)
		}
		if len(keys) != len(vals) {
			log.Fatal().Str("headerRoleMap", headerRoleMap).Strs("keys", keys).Strs("vals", vals).Msg("unexpected number of key value pairs in role map")
		}
	}

	if cookieDomain != "" && cookieDomain != "localhost" {
		cookieDomain = "." + cookieDomain
	}

	log.Info().Str("tenantID", tenantID).Str("clientId", clientId).Str("clientSecret", maskClientSecret(clientSecret, 3)).Str("callbackUrl", callbackURL).Str("cookieDomain", cookieDomain).Msg("environment variables")
	if tenantID == "" {
		log.Fatal().Msg("tenant id missing, pass it via AAD_TENANT_ID environment variable, receive it from app registration overview page, it is called \"Directory (tenant) ID\"")
	}
	if clientId == "" {
		log.Fatal().Msg("client id missing, pass it via AAD_CLIENT_ID environment variable, receive it from app registration overview page, it is called \"Application (client) ID\"")
	}
	if clientSecret == "" {
		log.Fatal().Msg("client secret missing, pass it via AAD_CLIEN_SECRET environment variable, receive it from app registration overview page, in sidebar navigate to \"Certificates & secrets\" section and add new client secret")
	}
	if callbackURL == "" {
		log.Fatal().Msg("callback url missing, pass it via AAD_CALLBACK_URL environment variable, receive it from app registration overview page, in sidebar navigate to \"Authentication\" section and add url to \"Redirect URIs\"")
	}
	if cookieDomain == "" {
		log.Fatal().Msg("cookie domain missing, pass it via AAD_COOKIE_DOMAIN environment variable, it should be parent domain of your proxy, e.g. if your proxy is \"aad.contoso.com\" then use \"contoso.com\", if not set to localhost, cookie will be prefixed with dot, so will work for all subdomain")
	}
	if cookieName == "" {
		log.Fatal().Msg("cookie name missing, pass it via AAD_COOKIE_NAME environment variable, should be something like \"aad\"")
	}

	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("https://sts.windows.net/%s/", tenantID))
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create odic provider")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientId})
	oauth2 := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  callbackURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// http.Handle("/metrics", promhttp.Handler())
	http.Handle("/resources/", http.FileServer(http.FS(resources)))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			log.Warn().Err(err).Str("handler", "home").Msg("unable to retrieve id_token cookie")
			// http.Error(w, "Unauthorized", http.StatusUnauthorized)
			errorTemplate.Execute(w, err)
			return
		}

		idToken, err := verifier.Verify(ctx, cookie.Value)
		if err != nil {
			log.Warn().Err(err).Str("handler", "home").Msg("unable to verify id_token")
			// http.Error(w, "Unauthorized", http.StatusUnauthorized)
			errorTemplate.Execute(w, err)
			return
		}

		user := User{}
		idToken.Claims(&user)
		// data, err := json.Marshal(user)
		// if err != nil {
		// 	log.Warn().Err(err).Str("handler", "home").Msg("unable to decode id_token claims")
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// 	return
		// }
		// w.Write(data)
		homeTemplate.Execute(w, user)
	})

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			log.Info().Err(err).Str("handler", "check").Msg("unable to get id_token cookie")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		idToken, err := verifier.Verify(ctx, cookie.Value)
		if err != nil {
			log.Warn().Err(err).Str("handler", "check").Msg("unable to verify id_token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user := User{}
		idToken.Claims(&user)
		email := strings.ToLower(user.Email)
		w.Header().Set(headerId, user.ID)
		w.Header().Set(headerName, user.Name)
		w.Header().Set(headerUsername, email[:strings.Index(email, "@")])
		w.Header().Set(headerEmail, email)
		w.Header().Set(headerRoles, strings.Join(user.Roles[:], ","))
		if len(keys) > 0 && len(vals) > 0 {
			v := ""
			for ki, k := range keys {
				for _, r := range user.Roles {
					if k == r {
						v = vals[ki]
					}
				}
			}
			if v != "" {
				w.Header().Set(headerRole, v)
			}
			log.Info().Str("handler", "check").Str("id", user.ID).Str("email", user.Email).Str("name", user.Name).Strs("roles", user.Roles).Str("role", v).Msg("success")
		} else {
			log.Info().Str("handler", "check").Str("id", user.ID).Str("email", user.Email).Str("name", user.Name).Strs("roles", user.Roles).Msg("success")
		}
		fmt.Fprintf(w, "OK")
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		rd := r.URL.Query().Get("rd")
		if rd == "" {
			rd = "/"
		}

		state, err := randString(16)
		if err != nil {
			log.Warn().Err(err).Str("handler", "login").Msg("unable create state")
			// http.Error(w, "Internal error", http.StatusInternalServerError)
			errorTemplate.Execute(w, err)
			return
		}
		nonce, err := randString(16)
		if err != nil {
			log.Warn().Err(err).Str("handler", "login").Msg("unable create nonce")
			// http.Error(w, "Internal error", http.StatusInternalServerError)
			errorTemplate.Execute(w, err)
			return
		}

		ttl := int((5 * time.Minute).Seconds())
		setCallbackCookie(w, r, "rd", rd, cookieDomain, ttl)
		setCallbackCookie(w, r, "state", state, cookieDomain, ttl)
		setCallbackCookie(w, r, "nonce", nonce, cookieDomain, ttl)

		url := oauth2.AuthCodeURL(state, oidc.Nonce(nonce))
		log.Info().Str("handler", "login").Str("rd", rd).Str("state", state).Str("nonce", nonce).Str("url", url).Msg("success, redirecting")
		http.Redirect(w, r, url, http.StatusFound)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie("state")
		if err != nil {
			log.Warn().Err(err).Str("handler", "callback").Msg("unable to get state from cookie")
			// http.Error(w, "state not found", http.StatusBadRequest)
			errorTemplate.Execute(w, err)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			log.Warn().Err(err).Str("handler", "callback").Msg("state from cookie and identity provider did not match")
			// http.Error(w, "state did not match", http.StatusBadRequest)
			errorTemplate.Execute(w, err)
			return
		}

		oauth2Token, err := oauth2.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Warn().Err(err).Str("handler", "callback").Msg("unable to exchange code for access token")
			// http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			errorTemplate.Execute(w, err)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Warn().Str("handler", "callback").Msg("unable to get id_token from oauth2 token")
			// http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			errorTemplate.Execute(w, err)
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Warn().Err(err).Str("handler", "callback").Msg("unable to verify id_token")
			// http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			errorTemplate.Execute(w, err)
			return
		}

		nonce, err := r.Cookie("nonce")
		if err != nil {
			log.Warn().Err(err).Str("handler", "callback").Msg("unable get nonce from cookie")
			// http.Error(w, "nonce not found", http.StatusBadRequest)
			errorTemplate.Execute(w, err)
			return
		}
		if idToken.Nonce != nonce.Value {
			log.Warn().Str("handler", "callback").Msg("nonce in cookie and id_token did not match")
			// http.Error(w, "nonce did not match", http.StatusBadRequest)
			errorTemplate.Execute(w, err)
			return
		}

		setCallbackCookie(w, r, cookieName, rawIDToken, cookieDomain, int(time.Until(oauth2Token.Expiry).Seconds()))

		rd, err := r.Cookie("rd")
		if err != nil || rd.Value == "" {
			rd.Value = "/"
		}

		user := User{}
		idToken.Claims(&user)

		log.Info().Str("handler", "callback").Str("id", user.ID).Str("email", user.Email).Str("name", user.Name).Str("rd", rd.Value).Msg("success, redirecting")

		http.Redirect(w, r, rd.Value, http.StatusFound)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		setCallbackCookie(w, r, cookieName, "", cookieDomain, 0)

		rd := r.URL.Query().Get("rd")
		if rd == "" {
			rd = "/"
		}

		log.Info().Str("handler", "logout").Str("rd", rd).Msg("success, redirecting")
		http.Redirect(w, r, rd, http.StatusFound)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	log.Info().Msg("starting server on 0.0.0.0:8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to start server")
	}
}

type User struct {
	ID    string   `json:"sub"`
	Name  string   `json:"name"`
	Email string   `json:"unique_name"` // unique_name, upn
	Roles []string `json:"roles"`
}

func maskClientSecret(secret string, num int) string {
	if secret == "" {
		return ""
	}

	if len(secret) < num+1 {
		return strings.Repeat("*", len(secret))
	}

	return secret[:num] + strings.Repeat("*", len(secret)-num)
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value, domain string, ttl int) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		MaxAge:   ttl,
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}
