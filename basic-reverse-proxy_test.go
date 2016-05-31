package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuthMissingConfig(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}
	auth := BasicAuth{}
	handler := auth.Handle(okHandler)
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth("", "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestBasicAuthNotProvided(t *testing.T) {
	okBody := []byte("abc")
	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write(okBody)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		log.Fatal(err)
	}
	w := httptest.NewRecorder()

	auth := BasicAuth{"uname", "passw"}
	handler := auth.Handle(okHandler)
	handler.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expeted status code 400, got %d", w.Code)
	}

	if w.Body.String() == string(okBody) {
		t.Fatalf("okBody was not expected")
	}
}

func TestBasicAuthInvalid(t *testing.T) {
	okBody := []byte("abc")
	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write(okBody)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth("uname", "wrongpasswd")
	w := httptest.NewRecorder()

	auth := BasicAuth{"uname", "passw"}
	handler := auth.Handle(okHandler)
	handler.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expeted status code 401, got %d", w.Code)
	}

	if w.Body.String() == string(okBody) {
		t.Fatalf("okBody not expected")
	}
}

func TestBasicAuthOk(t *testing.T) {
	okBody := []byte("abc")
	okHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write(okBody)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth("uname", "passw")
	w := httptest.NewRecorder()

	auth := BasicAuth{"uname", "passw"}
	handler := auth.Handle(okHandler)
	handler.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expeted status code 200, got %d", w.Code)
	}
	if w.Body.String() != string(okBody) {
		t.Fatalf("okBody expected")
	}

}
