package heroku

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"code.google.com/p/go-uuid/uuid"
)

var DefaultTransport = &Transport{}

var DefaultClient = &http.Client{
	Transport: DefaultTransport,
}

type Transport struct {
	// Username is the HTTP basic auth username for API calls made by this Client.
	Username string

	// Password is the HTTP basic auth password for API calls made by this Client.
	Password string

	// UserAgent to be provided in API requests. Set to DefaultUserAgent if not
	// specified.
	UserAgent string

	// Debug mode can be used to dump the full request and response to stdout.
	Debug bool

	// AdditionalHeaders are extra headers to add to each HTTP request sent by
	// this Client.
	AdditionalHeaders http.Header

	// Transport is the HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	Transport http.RoundTripper
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Transport == nil {
		t.Transport = http.DefaultTransport
	}

	if t.UserAgent != "" {
		req.Header.Set("User-Agent", t.UserAgent)
	}

	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	req.Header.Set("Request-Id", uuid.New())
	if req.Header.Get("Authorization") == "" {
		req.SetBasicAuth(t.Username, t.Password)
	}
	for k, v := range t.AdditionalHeaders {
		req.Header[k] = v
	}

	if t.Debug {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			log.Println(err)
		} else {
			os.Stderr.Write(dump)
			os.Stderr.Write([]byte{'\n', '\n'})
		}
	}

	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if t.Debug {
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			log.Println(err)
		} else {
			os.Stderr.Write(dump)
			os.Stderr.Write([]byte{'\n'})
		}
	}

	if err = checkResponse(resp); err != nil {
		return nil, err
	}

	return resp, nil
}

type Error struct {
	error
	ID  string
	URL string
}

func checkResponse(resp *http.Response) error {
	if resp.StatusCode/100 != 2 { // 200, 201, 202, etc
		var e struct {
			Message string
			ID      string
			URL     string `json:"url"`
		}
		err := json.NewDecoder(resp.Body).Decode(&e)
		if err != nil {
			return fmt.Errorf("encountered an error : %s", resp.Status)
		}
		return Error{error: errors.New(e.Message), ID: e.ID, URL: e.URL}
	}
	if msg := resp.Header.Get("X-Heroku-Warning"); msg != "" {
		log.Println(os.Stderr, strings.TrimSpace(msg))
	}
	return nil
}
