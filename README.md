# Heroku Platform API

[![GoDoc](https://godoc.org/github.com/heroku/heroku-go?status.svg)](https://godoc.org/github.com/heroku/heroku-go)

An API client interface for Heroku Platform API for the Go (golang) programming language.

Please note: [major version changes](#major-version-changes).

## Usage

	$ go mod init myproj
	$ go mod get -u github.com/heroku/heroku-go/v6
	$ cd myproj

## Example

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	heroku "github.com/heroku/heroku-go/v6"
)

var (
	apiKey = flag.String("api-key", "", "Heroku API key")
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	heroku.DefaultTransport.BearerToken = *apiKey

	h := heroku.NewService(heroku.DefaultClient)
	addons, err := h.AddOnList(context.TODO(), &heroku.ListRange{Field: "name"})
	if err != nil {
		log.Fatal(err)
	}
	for _, addon := range addons {
		fmt.Println(addon.Name)
	}
}
```

## Major Version Changes

### `v5` → `v6`

The Formation type's `Size` string property moved to `DynoSize` struct property, which can identify a dyno size by ID or Name.

In `v5`:

```go
import (
	heroku "github.com/heroku/heroku-go/v5"
)

opts := heroku.FormationUpdateOpts{}
newSize := "standard-1x"
opts.Size = &newSize
```

…becomes in `v6`…

```go
import (
	heroku "github.com/heroku/heroku-go/v6"
)

opts := heroku.FormationUpdateOpts{}
newSize := "standard-1x"
opts.DynoSize = &struct {
	ID   *string `json:"id,omitempty" url:"id,omitempty,key"`     // unique identifier of the dyno size
	Name *string `json:"name,omitempty" url:"name,omitempty,key"` // name of the dyno size
}{
	Name: &newSize,
}
```

## Development

### Update Client for Schema

This client is auto-generated from the JSON Schema published by the Heroku Platform API.

To fetch the current `schema.json` and generate an updated client:
```console
make generate
```

To use the existing `schema.json` to generate an updated client:
```console
UPDATE_SCHEMA=0 make generate
```

See [`script/generate`](script/generate) for more details.
