package heroku

import (
	"fmt"
	"net/http"

	"github.com/cenkalti/backoff"
)

func RoundTripWithRetryBackoff(req *http.Request) (*http.Response, error) {
	var lastResponse *http.Response
	var lastError error

	retryableRoundTrip := func() error {
		lastResponse, lastError = http.DefaultTransport.RoundTrip(req)
		// Detect Heroku API rate limiting
		// https://devcenter.heroku.com/articles/platform-api-reference#client-error-responses
		if lastResponse.StatusCode == 429 {
			return fmt.Errorf("Heroku API rate limited: 429 Too Many Requests")
		}
		return nil
	}

	err := backoff.Retry(retryableRoundTrip, backoff.NewExponentialBackOff())
	// Propagate the rate limit error when retries eventually fail.
	if err != nil {
		if lastResponse != nil {
			lastResponse.Body.Close()
		}
		return nil, err
	}
	// Propagate all other response errors.
	if lastError != nil {
		if lastResponse != nil {
			lastResponse.Body.Close()
		}
		return nil, lastError
	}

	return lastResponse, nil
}
