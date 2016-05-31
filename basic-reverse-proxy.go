package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func main() {
	var configFlag = flag.String("config", "basic-reverse-proxy.json", "configuration json file")
	flag.Parse()
	configData, err := ioutil.ReadFile(*configFlag)
	if err != nil {
		log.Fatal(err)
	}
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatal(err)
	}

	for _, e := range config.Entries {
		u, err := url.Parse(e.Upstream)
		if err != nil {
			panic(err)
		}
		revproxy := NewReverseProxy(u)
		http.Handle(e.Path, config.Auth.Handle(revproxy.ServeHTTP))
		log.Printf("added proxy path %s for %s", e.Path, u.String())
	}
	log.Fatal(http.ListenAndServe(config.Addr, nil))
}

// Config is the configuration struct
type Config struct {
	Auth    BasicAuth `json:"auth"`
	Entries []Entry   `json:"entries"`
	Addr    string    `json:"addr"`
}

// Entry is a single (http) url to proxy.
type Entry struct {
	Upstream string `json:"upstream"` // hostport of http server to proxy
	Path     string `json:"path"`     // origin path
}

// NewReverseProxy targets a single URL
func NewReverseProxy(target *url.URL) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		req.URL = target
	}
	return &httputil.ReverseProxy{Director: director}
}

// BasicAuth is a basic auth handlerfunc
type BasicAuth struct {
	Username string
	Password string
}

func (b BasicAuth) Handle(pass http.HandlerFunc) http.HandlerFunc {
	if b.Username == "" || b.Password == "" {
		panic("Username and password must be supplied")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(auth) != 2 || auth[0] != "Basic" {
			http.Error(w, "authorization failed", http.StatusBadRequest)
			return
		}
		payload, _ := base64.StdEncoding.DecodeString(auth[1])
		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || b.Username != pair[0] || b.Password != pair[1] {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}
		pass(w, r)
	}
}
