package heroku

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"time"
)

const (
	Version          = "v3"
	DefaultAPIURL    = "https://api.heroku.com"
	DefaultUserAgent = "heroku/" + Version + " (" + runtime.GOOS + "; " + runtime.GOARCH + ")"
)

// Service represents your API.
type Service struct {
	client *http.Client
}

// Create a Service using the given, if none is provided
// it uses http.DefaultClient.
func NewService(c *http.Client) *Service {
	if c == nil {
		c = http.DefaultClient
	}
	return &Service{
		client: c,
	}
}

// Generates an HTTP request, but does not perform the request.
func (s *Service) NewRequest(method, path string, body interface{}) (*http.Request, error) {
	var ctype string
	var rbody io.Reader
	switch t := body.(type) {
	case nil:
	case string:
		rbody = bytes.NewBufferString(t)
	case io.Reader:
		rbody = t
	default:
		v := reflect.ValueOf(body)
		if !v.IsValid() {
			break
		}
		if v.Type().Kind() == reflect.Ptr {
			v = reflect.Indirect(v)
			if !v.IsValid() {
				break
			}
		}
		j, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rbody = bytes.NewReader(j)
		ctype = "application/json"
	}
	req, err := http.NewRequest(method, DefaultAPIURL+path, rbody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", DefaultUserAgent)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	return req, nil
}

// Sends a request and decodes the response into v.
func (s *Service) Do(v interface{}, method, path string, body interface{}, lr *ListRange) error {
	req, err := s.NewRequest(method, path, body)
	if err != nil {
		return err
	}
	if lr != nil {
		lr.SetHeader(req)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch t := v.(type) {
	case nil:
	case io.Writer:
		_, err = io.Copy(t, resp.Body)
	default:
		err = json.NewDecoder(resp.Body).Decode(v)
	}
	return err
}
func (s *Service) Get(v interface{}, path string, lr *ListRange) error {
	return s.Do(v, "GET", path, nil, lr)
}
func (s *Service) Patch(v interface{}, path string, body interface{}) error {
	return s.Do(v, "PATCH", path, body, nil)
}
func (s *Service) Post(v interface{}, path string, body interface{}) error {
	return s.Do(v, "POST", path, body, nil)
}
func (s *Service) Put(v interface{}, path string, body interface{}) error {
	return s.Do(v, "PUT", path, body, nil)
}
func (s *Service) Delete(path string) error {
	return s.Do(nil, "DELETE", path, nil, nil)
}

type ListRange struct {
	Field      string
	Max        int
	Descending bool
	FirstId    string
	LastId     string
}

func (lr *ListRange) SetHeader(req *http.Request) {
	var hdrval string
	if lr.Field != "" {
		hdrval += lr.Field + " "
	}
	hdrval += lr.FirstId + ".." + lr.LastId
	if lr.Max != 0 {
		hdrval += fmt.Sprintf("; max=%d", lr.Max)
		if lr.Descending {
			hdrval += ", "
		}
	}
	if lr.Descending {
		hdrval += ", order=desc"
	}
	req.Header.Set("Range", hdrval)
	return
}

// Bool allocates a new int value returns a pointer to it.
func Bool(v bool) *bool {
	p := new(bool)
	*p = v
	return p
}

// Int64 allocates a new int64 value returns a pointer to it.
func Int64(v int64) *int64 {
	p := new(int64)
	*p = v
	return p
}

// Float64 allocates a new float64 value returns a pointer to it.
func Float64(v float64) *float64 {
	p := new(float64)
	*p = v
	return p
}

// String allocates a new string value returns a pointer to it.
func String(v string) *string {
	p := new(string)
	*p = v
	return p
}

// Add-ons represent add-ons that have been provisioned for an app.
type Addon struct {
	ConfigVars []string  `json:"config_vars"`
	CreatedAt  time.Time `json:"created_at"`
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Plan       struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"plan"` // identity of add-on plan
	ProviderID string    `json:"provider_id"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Create a new add-on.
func (s *Service) AddonCreate(appIdentity string, o struct {
	Config *map[string]string `json:"config,omitempty"` // custom add-on provisioning options
	Plan   string             `json:"plan"`
}) (*Addon, error) {
	var addon Addon
	return &addon, s.Post(&addon, fmt.Sprintf("/apps/%v/addons", appIdentity), o)
}

// Delete an existing add-on.
func (s *Service) AddonDelete(appIdentity string, addonIdentity string) error {
	return s.Delete(fmt.Sprintf("/apps/%v/addons/%v", appIdentity, addonIdentity))
}

// Info for an existing add-on.
func (s *Service) AddonInfo(appIdentity string, addonIdentity string) (*Addon, error) {
	var addon Addon
	return &addon, s.Get(&addon, fmt.Sprintf("/apps/%v/addons/%v", appIdentity, addonIdentity), nil)
}

// List existing add-ons.
func (s *Service) AddonList(appIdentity string, lr *ListRange) ([]*Addon, error) {
	var addonList []*Addon
	return addonList, s.Get(&addonList, fmt.Sprintf("/apps/%v/addons", appIdentity), lr)
}

// Update an existing add-on.
func (s *Service) AddonUpdate(appIdentity string, addonIdentity string, o struct {
	Plan string `json:"plan"`
}) (*Addon, error) {
	var addon Addon
	return &addon, s.Patch(&addon, fmt.Sprintf("/apps/%v/addons/%v", appIdentity, addonIdentity), o)
}

// An app feature represents a Heroku labs capability that can be
// enabled or disabled for an app on Heroku.
type AppFeature struct {
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description"`
	DocURL      string    `json:"doc_url"`
	Enabled     bool      `json:"enabled"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	State       string    `json:"state"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Info for an existing app feature.
func (s *Service) AppFeatureInfo(appIdentity string, appFeatureIdentity string) (*AppFeature, error) {
	var appFeature AppFeature
	return &appFeature, s.Get(&appFeature, fmt.Sprintf("/apps/%v/features/%v", appIdentity, appFeatureIdentity), nil)
}

// List existing app features.
func (s *Service) AppFeatureList(appIdentity string, lr *ListRange) ([]*AppFeature, error) {
	var appFeatureList []*AppFeature
	return appFeatureList, s.Get(&appFeatureList, fmt.Sprintf("/apps/%v/features", appIdentity), lr)
}

// Update an existing app feature.
func (s *Service) AppFeatureUpdate(appIdentity string, appFeatureIdentity string, o struct {
	Enabled bool `json:"enabled"`
}) (*AppFeature, error) {
	var appFeature AppFeature
	return &appFeature, s.Patch(&appFeature, fmt.Sprintf("/apps/%v/features/%v", appIdentity, appFeatureIdentity), o)
}

// Domains define what web routes should be routed to an app on Heroku.
type Domain struct {
	CreatedAt time.Time `json:"created_at"`
	Hostname  string    `json:"hostname"`
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Create a new domain.
func (s *Service) DomainCreate(appIdentity string, o struct {
	Hostname string `json:"hostname"`
}) (*Domain, error) {
	var domain Domain
	return &domain, s.Post(&domain, fmt.Sprintf("/apps/%v/domains", appIdentity), o)
}

// Delete an existing domain
func (s *Service) DomainDelete(appIdentity string, domainIdentity string) error {
	return s.Delete(fmt.Sprintf("/apps/%v/domains/%v", appIdentity, domainIdentity))
}

// Info for existing domain.
func (s *Service) DomainInfo(appIdentity string, domainIdentity string) (*Domain, error) {
	var domain Domain
	return &domain, s.Get(&domain, fmt.Sprintf("/apps/%v/domains/%v", appIdentity, domainIdentity), nil)
}

// List existing domains.
func (s *Service) DomainList(appIdentity string, lr *ListRange) ([]*Domain, error) {
	var domainList []*Domain
	return domainList, s.Get(&domainList, fmt.Sprintf("/apps/%v/domains", appIdentity), lr)
}

// Dynos encapsulate running processes of an app on Heroku.
type Dyno struct {
	Name      string    `json:"name"`
	AttachURL *string   `json:"attach_url"`
	Command   string    `json:"command"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	Release   struct {
		ID      string `json:"id"`
		Version int64  `json:"version"`
	} `json:"release"` // app release of the dyno
	Size      string    `json:"size"`
	State     string    `json:"state"`
	Type      string    `json:"type"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Create a new dyno.
func (s *Service) DynoCreate(appIdentity string, o struct {
	Attach  *bool              `json:"attach,omitempty"`
	Command string             `json:"command"`
	Env     *map[string]string `json:"env,omitempty"`
	Size    *string            `json:"size,omitempty"`
}) (*Dyno, error) {
	var dyno Dyno
	return &dyno, s.Post(&dyno, fmt.Sprintf("/apps/%v/dynos", appIdentity), o)
}

// Restart dyno.
func (s *Service) DynoRestart(appIdentity string, dynoIdentity string) error {
	return s.Delete(fmt.Sprintf("/apps/%v/dynos/%v", appIdentity, dynoIdentity))
}

// Restart all dynos
func (s *Service) DynoRestartAll(appIdentity string) error {
	return s.Delete(fmt.Sprintf("/apps/%v/dynos", appIdentity))
}

// Info for existing dyno.
func (s *Service) DynoInfo(appIdentity string, dynoIdentity string) (*Dyno, error) {
	var dyno Dyno
	return &dyno, s.Get(&dyno, fmt.Sprintf("/apps/%v/dynos/%v", appIdentity, dynoIdentity), nil)
}

// List existing dynos.
func (s *Service) DynoList(appIdentity string, lr *ListRange) ([]*Dyno, error) {
	var dynoList []*Dyno
	return dynoList, s.Get(&dynoList, fmt.Sprintf("/apps/%v/dynos", appIdentity), lr)
}

// Stacks are the different application execution environments available
// in the Heroku platform.
type Stack struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Stack info.
func (s *Service) StackInfo(stackIdentity string) (*Stack, error) {
	var stack Stack
	return &stack, s.Get(&stack, fmt.Sprintf("/stacks/%v", stackIdentity), nil)
}

// List available stacks.
func (s *Service) StackList(lr *ListRange) ([]*Stack, error) {
	var stackList []*Stack
	return stackList, s.Get(&stackList, fmt.Sprintf("/stacks"), lr)
}

// An account represents an individual signed up to use the Heroku
// platform.
type Account struct {
	AllowTracking bool      `json:"allow_tracking"`
	Beta          bool      `json:"beta"`
	CreatedAt     time.Time `json:"created_at"`
	Email         string    `json:"email"`
	ID            string    `json:"id"`
	LastLogin     time.Time `json:"last_login"`
	UpdatedAt     time.Time `json:"updated_at"`
	Verified      bool      `json:"verified"`
}

// Info for account.
func (s *Service) AccountInfo() (*Account, error) {
	var account Account
	return &account, s.Get(&account, fmt.Sprintf("/account"), nil)
}

// Update account.
func (s *Service) AccountUpdate(o struct {
	AllowTracking *bool   `json:"allow_tracking,omitempty"`
	Beta          *bool   `json:"beta,omitempty"`
	Name          *string `json:"name,omitempty"`
	Password      string  `json:"password"`
}) (*Account, error) {
	var account Account
	return &account, s.Patch(&account, fmt.Sprintf("/account"), o)
}

// Change Email for account.
func (s *Service) AccountChangeEmail(o struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}) (*Account, error) {
	var account Account
	return &account, s.Patch(&account, fmt.Sprintf("/account"), o)
}

// Change Password for account.
func (s *Service) AccountChangePassword(o struct {
	NewPassword string `json:"new_password"`
	Password    string `json:"password"`
}) (*Account, error) {
	var account Account
	return &account, s.Patch(&account, fmt.Sprintf("/account"), o)
}

// Config Vars allow you to manage the configuration information
// provided to an app on Heroku.
type ConfigVar map[string]string

// Get config-vars for app.
func (s *Service) ConfigVarInfo(appIdentity string) (*ConfigVar, error) {
	var configVar ConfigVar
	return &configVar, s.Get(&configVar, fmt.Sprintf("/apps/%v/config-vars", appIdentity), nil)
}

// Update config-vars for app. You can update existing config-vars by
// setting them again, and remove by setting it to `NULL`.
func (s *Service) ConfigVarUpdate(appIdentity string, o map[string]string) (*ConfigVar, error) {
	var configVar ConfigVar
	return &configVar, s.Patch(&configVar, fmt.Sprintf("/apps/%v/config-vars", appIdentity), o)
}

// OAuth grants are used to obtain authorizations on behalf of a user.
// For more information please refer to the [Heroku OAuth
// documentation](https://devcenter.heroku.com/articles/oauth)
type OAuthGrant struct{}

// A region represents a geographic location in which your application
// may run.
type Region struct {
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Info for existing region.
func (s *Service) RegionInfo(regionIdentity string) (*Region, error) {
	var region Region
	return &region, s.Get(&region, fmt.Sprintf("/regions/%v", regionIdentity), nil)
}

// List existing regions.
func (s *Service) RegionList(lr *ListRange) ([]*Region, error) {
	var regionList []*Region
	return regionList, s.Get(&regionList, fmt.Sprintf("/regions"), lr)
}

// An app transfer represents a two party interaction for transferring
// ownership of an app.
type AppTransfer struct {
	App struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"app"` // app involved in the transfer
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	Owner     struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	} `json:"owner"` // identity of the owner of the transfer
	Recipient struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	} `json:"recipient"` // identity of the recipient of the transfer
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Create a new app transfer.
func (s *Service) AppTransferCreate(o struct {
	App       string `json:"app"`
	Recipient string `json:"recipient"`
}) (*AppTransfer, error) {
	var appTransfer AppTransfer
	return &appTransfer, s.Post(&appTransfer, fmt.Sprintf("/account/app-transfers"), o)
}

// Delete an existing app transfer
func (s *Service) AppTransferDelete(appTransferIdentity string) error {
	return s.Delete(fmt.Sprintf("/account/app-transfers/%v", appTransferIdentity))
}

// Info for existing app transfer.
func (s *Service) AppTransferInfo(appTransferIdentity string) (*AppTransfer, error) {
	var appTransfer AppTransfer
	return &appTransfer, s.Get(&appTransfer, fmt.Sprintf("/account/app-transfers/%v", appTransferIdentity), nil)
}

// List existing apps transfers.
func (s *Service) AppTransferList(lr *ListRange) ([]*AppTransfer, error) {
	var appTransferList []*AppTransfer
	return appTransferList, s.Get(&appTransferList, fmt.Sprintf("/account/app-transfers"), lr)
}

// Update an existing app transfer.
func (s *Service) AppTransferUpdate(appTransferIdentity string, o struct {
	State string `json:"state"`
}) (*AppTransfer, error) {
	var appTransfer AppTransfer
	return &appTransfer, s.Patch(&appTransfer, fmt.Sprintf("/account/app-transfers/%v", appTransferIdentity), o)
}

// An app represents the program that you would like to deploy and run
// on Heroku.
type App struct {
	ArchivedAt *time.Time `json:"archived_at"`
	CreatedAt  time.Time  `json:"created_at"`
	ID         string     `json:"id"`
	Owner      struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	} `json:"owner"` // identity of app owner
	WebURL                       string     `json:"web_url"`
	BuildpackProvidedDescription *string    `json:"buildpack_provided_description"`
	Name                         string     `json:"name"`
	ReleasedAt                   *time.Time `json:"released_at"`
	RepoSize                     *int64     `json:"repo_size"`
	SlugSize                     *int64     `json:"slug_size"`
	UpdatedAt                    time.Time  `json:"updated_at"`
	Maintenance                  bool       `json:"maintenance"`
	Stack                        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"stack"` // identity of app stack
	GitURL string `json:"git_url"`
	Region struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"region"` // identity of app region
}

// Create a new app.
func (s *Service) AppCreate(o struct {
	Name   *string `json:"name,omitempty"`
	Region *string `json:"region,omitempty"`
	Stack  *string `json:"stack,omitempty"`
}) (*App, error) {
	var app App
	return &app, s.Post(&app, fmt.Sprintf("/apps"), o)
}

// Delete an existing app.
func (s *Service) AppDelete(appIdentity string) error {
	return s.Delete(fmt.Sprintf("/apps/%v", appIdentity))
}

// Info for existing app.
func (s *Service) AppInfo(appIdentity string) (*App, error) {
	var app App
	return &app, s.Get(&app, fmt.Sprintf("/apps/%v", appIdentity), nil)
}

// List existing apps.
func (s *Service) AppList(lr *ListRange) ([]*App, error) {
	var appList []*App
	return appList, s.Get(&appList, fmt.Sprintf("/apps"), lr)
}

// Update an existing app.
func (s *Service) AppUpdate(appIdentity string, o struct {
	Maintenance *bool   `json:"maintenance,omitempty"`
	Name        *string `json:"name,omitempty"`
}) (*App, error) {
	var app App
	return &app, s.Patch(&app, fmt.Sprintf("/apps/%v", appIdentity), o)
}

// A collaborator represents an account that has been given access to an
// app on Heroku.
type Collaborator struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
	User      struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	} `json:"user"` // identity of collaborated account
}

// Create a new collaborator.
func (s *Service) CollaboratorCreate(appIdentity string, o struct {
	Silent *bool  `json:"silent,omitempty"`
	User   string `json:"user"`
}) (*Collaborator, error) {
	var collaborator Collaborator
	return &collaborator, s.Post(&collaborator, fmt.Sprintf("/apps/%v/collaborators", appIdentity), o)
}

// Delete an existing collaborator.
func (s *Service) CollaboratorDelete(appIdentity string, collaboratorIdentity string) error {
	return s.Delete(fmt.Sprintf("/apps/%v/collaborators/%v", appIdentity, collaboratorIdentity))
}

// Info for existing collaborator.
func (s *Service) CollaboratorInfo(appIdentity string, collaboratorIdentity string) (*Collaborator, error) {
	var collaborator Collaborator
	return &collaborator, s.Get(&collaborator, fmt.Sprintf("/apps/%v/collaborators/%v", appIdentity, collaboratorIdentity), nil)
}

// List existing collaborators.
func (s *Service) CollaboratorList(appIdentity string, lr *ListRange) ([]*Collaborator, error) {
	var collaboratorList []*Collaborator
	return collaboratorList, s.Get(&collaboratorList, fmt.Sprintf("/apps/%v/collaborators", appIdentity), lr)
}

// Keys represent public SSH keys associated with an account and are
// used to authorize accounts as they are performing git operations.
type Key struct {
	CreatedAt   time.Time `json:"created_at"`
	Email       string    `json:"email"`
	Fingerprint string    `json:"fingerprint"`
	ID          string    `json:"id"`
	PublicKey   string    `json:"public_key"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Create a new key.
func (s *Service) KeyCreate(o struct {
	PublicKey string `json:"public_key"`
}) (*Key, error) {
	var key Key
	return &key, s.Post(&key, fmt.Sprintf("/account/keys"), o)
}

// Delete an existing key
func (s *Service) KeyDelete(keyIdentity string) error {
	return s.Delete(fmt.Sprintf("/account/keys/%v", keyIdentity))
}

// Info for existing key.
func (s *Service) KeyInfo(keyIdentity string) (*Key, error) {
	var key Key
	return &key, s.Get(&key, fmt.Sprintf("/account/keys/%v", keyIdentity), nil)
}

// List existing keys.
func (s *Service) KeyList(lr *ListRange) ([]*Key, error) {
	var keyList []*Key
	return keyList, s.Get(&keyList, fmt.Sprintf("/account/keys"), lr)
}

// [Log
// drains](https://devcenter.heroku.com/articles/logging#syslog-drains)
// provide a way to forward your Heroku logs to an external syslog
// server for long-term archiving. This external service must be
// configured to receive syslog packets from Heroku, whereupon its URL
// can be added to an app using this API. Some addons will add a log
// drain when they are provisioned to an app. These drains can only be
// removed by removing the add-on.
type LogDrain struct {
	Addon *struct {
		ID string `json:"id"`
	} `json:"addon"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	UpdatedAt time.Time `json:"updated_at"`
	URL       string    `json:"url"`
}

// Create a new log drain.
func (s *Service) LogDrainCreate(appIdentity string, o struct {
	URL string `json:"url"`
}) (*LogDrain, error) {
	var logDrain LogDrain
	return &logDrain, s.Post(&logDrain, fmt.Sprintf("/apps/%v/log-drains", appIdentity), o)
}

// Delete an existing log drain. Log drains added by add-ons can only be
// removed by removing the add-on.
func (s *Service) LogDrainDelete(appIdentity string, logDrainIdentity string) error {
	return s.Delete(fmt.Sprintf("/apps/%v/log-drains/%v", appIdentity, logDrainIdentity))
}

// Info for existing log drain.
func (s *Service) LogDrainInfo(appIdentity string, logDrainIdentity string) (*LogDrain, error) {
	var logDrain LogDrain
	return &logDrain, s.Get(&logDrain, fmt.Sprintf("/apps/%v/log-drains/%v", appIdentity, logDrainIdentity), nil)
}

// List existing log drains.
func (s *Service) LogDrainList(appIdentity string, lr *ListRange) ([]*LogDrain, error) {
	var logDrainList []*LogDrain
	return logDrainList, s.Get(&logDrainList, fmt.Sprintf("/apps/%v/log-drains", appIdentity), lr)
}

// A log session is a reference to the http based log stream for an app.
type LogSession struct {
	CreatedAt  time.Time `json:"created_at"`
	ID         string    `json:"id"`
	LogplexURL string    `json:"logplex_url"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Create a new log session.
func (s *Service) LogSessionCreate(appIdentity string, o struct {
	Dyno   *string `json:"dyno,omitempty"`
	Lines  *int64  `json:"lines,omitempty"`
	Source *string `json:"source,omitempty"`
	Tail   *bool   `json:"tail,omitempty"`
}) (*LogSession, error) {
	var logSession LogSession
	return &logSession, s.Post(&logSession, fmt.Sprintf("/apps/%v/log-sessions", appIdentity), o)
}

// OAuth authorizations represent clients that a Heroku user has
// authorized to automate, customize or extend their usage of the
// platform. For more information please refer to the [Heroku OAuth
// documentation](https://devcenter.heroku.com/articles/oauth)
type OAuthAuthorization struct {
	AccessToken *struct {
		ExpiresIn *int64 `json:"expires_in"`
		ID        string `json:"id"`
		Token     string `json:"token"`
	} `json:"access_token"` // access token for this authorization
	Client *struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		RedirectURI string `json:"redirect_uri"`
	} `json:"client"` // identifier of the client that obtained this authorization, if any
	CreatedAt time.Time `json:"created_at"`
	Grant     *struct {
		Code      string `json:"code"`
		ExpiresIn int64  `json:"expires_in"`
		ID        string `json:"id"`
	} `json:"grant"` // this authorization's grant
	ID           string `json:"id"`
	RefreshToken *struct {
		ExpiresIn *int64 `json:"expires_in"`
		ID        string `json:"id"`
		Token     string `json:"token"`
	} `json:"refresh_token"` // refresh token for this authorization
	Scope     []string  `json:"scope"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Create a new OAuth authorization.
func (s *Service) OAuthAuthorizationCreate(o struct {
	Client      *string  `json:"client,omitempty"`
	Description *string  `json:"description,omitempty"`
	ExpiresIn   *int64   `json:"expires_in,omitempty"`
	Scope       []string `json:"scope"`
}) (*OAuthAuthorization, error) {
	var oauthAuthorization OAuthAuthorization
	return &oauthAuthorization, s.Post(&oauthAuthorization, fmt.Sprintf("/oauth/authorizations"), o)
}

// Delete OAuth authorization.
func (s *Service) OAuthAuthorizationDelete(oauthAuthorizationIdentity string) error {
	return s.Delete(fmt.Sprintf("/oauth/authorizations/%v", oauthAuthorizationIdentity))
}

// Info for an OAuth authorization.
func (s *Service) OAuthAuthorizationInfo(oauthAuthorizationIdentity string) (*OAuthAuthorization, error) {
	var oauthAuthorization OAuthAuthorization
	return &oauthAuthorization, s.Get(&oauthAuthorization, fmt.Sprintf("/oauth/authorizations/%v", oauthAuthorizationIdentity), nil)
}

// List OAuth authorizations.
func (s *Service) OAuthAuthorizationList(lr *ListRange) ([]*OAuthAuthorization, error) {
	var oauthAuthorizationList []*OAuthAuthorization
	return oauthAuthorizationList, s.Get(&oauthAuthorizationList, fmt.Sprintf("/oauth/authorizations"), lr)
}

// OAuth tokens provide access for authorized clients to act on behalf
// of a Heroku user to automate, customize or extend their usage of the
// platform. For more information please refer to the [Heroku OAuth
// documentation](https://devcenter.heroku.com/articles/oauth)
type OAuthToken struct {
	CreatedAt    time.Time `json:"created_at"`
	ID           string    `json:"id"`
	RefreshToken struct {
		ExpiresIn *int64 `json:"expires_in"`
		ID        string `json:"id"`
		Token     string `json:"token"`
	} `json:"refresh_token"` // refresh token for this authorization
	AccessToken struct {
		ExpiresIn *int64 `json:"expires_in"`
		ID        string `json:"id"`
		Token     string `json:"token"`
	} `json:"access_token"` // current access token
	Authorization struct {
		ID string `json:"id"`
	} `json:"authorization"` // authorization for this set of tokens
	Client *struct {
		Secret string `json:"secret"`
	} `json:"client"` // OAuth client secret used to obtain token
	Grant struct {
		Code string `json:"code"`
		Type string `json:"type"`
	} `json:"grant"` // grant used on the underlying authorization
	Session struct {
		ID string `json:"id"`
	} `json:"session"` // OAuth session using this token
	UpdatedAt time.Time `json:"updated_at"`
	User      struct {
		ID string `json:"id"`
	} `json:"user"` // Reference to the user associated with this token
}

// Create a new OAuth token.
func (s *Service) OAuthTokenCreate(o struct {
	Client struct {
		Secret *string `json:"secret,omitempty"`
	} `json:"client"`
	Grant struct {
		Code *string `json:"code,omitempty"`
		Type *string `json:"type,omitempty"`
	} `json:"grant"`
	RefreshToken struct {
		Token *string `json:"token,omitempty"`
	} `json:"refresh_token"`
}) (*OAuthToken, error) {
	var oauthToken OAuthToken
	return &oauthToken, s.Post(&oauthToken, fmt.Sprintf("/oauth/tokens"), o)
}

// Rate Limit represents the number of request tokens each account
// holds. Requests to this endpoint do not count towards the rate limit.
type RateLimit struct {
	Remaining int64 `json:"remaining"`
}

// Info for rate limits.
func (s *Service) RateLimitInfo() (*RateLimit, error) {
	var rateLimit RateLimit
	return &rateLimit, s.Get(&rateLimit, fmt.Sprintf("/account/rate-limits"), nil)
}

// A release represents a combination of code, config vars and add-ons
// for an app on Heroku.
type Release struct {
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description"`
	ID          string    `json:"id"`
	UpdatedAt   time.Time `json:"updated_at"`
	Slug        *struct {
		ID string `json:"id"`
	} `json:"slug"` // slug running in this release
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"` // user that created the release
	Version int64 `json:"version"`
}

// Info for existing release.
func (s *Service) ReleaseInfo(appIdentity string, releaseIdentity string) (*Release, error) {
	var release Release
	return &release, s.Get(&release, fmt.Sprintf("/apps/%v/releases/%v", appIdentity, releaseIdentity), nil)
}

// List existing releases.
func (s *Service) ReleaseList(appIdentity string, lr *ListRange) ([]*Release, error) {
	var releaseList []*Release
	return releaseList, s.Get(&releaseList, fmt.Sprintf("/apps/%v/releases", appIdentity), lr)
}

// Create new release. The API cannot be used to create releases on
// Bamboo apps.
func (s *Service) ReleaseCreate(appIdentity string, o struct {
	Description *string `json:"description,omitempty"`
	Slug        string  `json:"slug"`
}) (*Release, error) {
	var release Release
	return &release, s.Post(&release, fmt.Sprintf("/apps/%v/releases", appIdentity), o)
}

// Rollback to an existing release.
func (s *Service) ReleaseRollback(appIdentity string, o struct {
	Release string `json:"release"`
}) (*Release, error) {
	var release Release
	return &release, s.Post(&release, fmt.Sprintf("/apps/%v/releases", appIdentity), o)
}

// An account feature represents a Heroku labs capability that can be
// enabled or disabled for an account on Heroku.
type AccountFeature struct {
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description"`
	DocURL      string    `json:"doc_url"`
	Enabled     bool      `json:"enabled"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	State       string    `json:"state"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Info for an existing account feature.
func (s *Service) AccountFeatureInfo(accountFeatureIdentity string) (*AccountFeature, error) {
	var accountFeature AccountFeature
	return &accountFeature, s.Get(&accountFeature, fmt.Sprintf("/account/features/%v", accountFeatureIdentity), nil)
}

// List existing account features.
func (s *Service) AccountFeatureList(lr *ListRange) ([]*AccountFeature, error) {
	var accountFeatureList []*AccountFeature
	return accountFeatureList, s.Get(&accountFeatureList, fmt.Sprintf("/account/features"), lr)
}

// Update an existing account feature.
func (s *Service) AccountFeatureUpdate(accountFeatureIdentity string, o struct {
	Enabled bool `json:"enabled"`
}) (*AccountFeature, error) {
	var accountFeature AccountFeature
	return &accountFeature, s.Patch(&accountFeature, fmt.Sprintf("/account/features/%v", accountFeatureIdentity), o)
}

// Add-on services represent add-ons that may be provisioned for apps.
type AddonService struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Info for existing addon-service.
func (s *Service) AddonServiceInfo(addonServiceIdentity string) (*AddonService, error) {
	var addonService AddonService
	return &addonService, s.Get(&addonService, fmt.Sprintf("/addon-services/%v", addonServiceIdentity), nil)
}

// List existing addon-services.
func (s *Service) AddonServiceList(lr *ListRange) ([]*AddonService, error) {
	var addonServiceList []*AddonService
	return addonServiceList, s.Get(&addonServiceList, fmt.Sprintf("/addon-services"), lr)
}

// The formation of processes that should be maintained for an app.
// Update the formation to scale processes or change dyno sizes.
// Available process type names and commands are defined by the
// `process_types` attribute for the [slug](#slug) currently released on
// an app.
type Formation struct {
	Command   string    `json:"command"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	Quantity  int64     `json:"quantity"`
	Size      string    `json:"size"`
	Type      string    `json:"type"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Info for a process type
func (s *Service) FormationInfo(appIdentity string, formationIdentity string) (*Formation, error) {
	var formation Formation
	return &formation, s.Get(&formation, fmt.Sprintf("/apps/%v/formation/%v", appIdentity, formationIdentity), nil)
}

// List process type formation
func (s *Service) FormationList(appIdentity string, lr *ListRange) ([]*Formation, error) {
	var formationList []*Formation
	return formationList, s.Get(&formationList, fmt.Sprintf("/apps/%v/formation", appIdentity), lr)
}

// Batch update process types
func (s *Service) FormationBatchUpdate(appIdentity string, o struct {
	Updates []map[string]string `json:"updates"` // Array with formation updates. Each element must have "process", the
	// id or name of the process type to be updated, and can optionally
	// update its "quantity" or "size".
}) (*Formation, error) {
	var formation Formation
	return &formation, s.Patch(&formation, fmt.Sprintf("/apps/%v/formation", appIdentity), o)
}

// Update process type
func (s *Service) FormationUpdate(appIdentity string, formationIdentity string, o struct {
	Quantity *int64  `json:"quantity,omitempty"`
	Size     *string `json:"size,omitempty"`
}) (*Formation, error) {
	var formation Formation
	return &formation, s.Patch(&formation, fmt.Sprintf("/apps/%v/formation/%v", appIdentity, formationIdentity), o)
}

// OAuth clients are applications that Heroku users can authorize to
// automate, customize or extend their usage of the platform. For more
// information please refer to the [Heroku OAuth
// documentation](https://devcenter.heroku.com/articles/oauth).
type OAuthClient struct {
	CreatedAt         time.Time `json:"created_at"`
	ID                string    `json:"id"`
	IgnoresDelinquent *bool     `json:"ignores_delinquent"`
	Name              string    `json:"name"`
	RedirectURI       string    `json:"redirect_uri"`
	Secret            string    `json:"secret"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Create a new OAuth client.
func (s *Service) OAuthClientCreate(o struct {
	Name        string `json:"name"`
	RedirectURI string `json:"redirect_uri"`
}) (*OAuthClient, error) {
	var oauthClient OAuthClient
	return &oauthClient, s.Post(&oauthClient, fmt.Sprintf("/oauth/clients"), o)
}

// Delete OAuth client.
func (s *Service) OAuthClientDelete(oauthClientIdentity string) error {
	return s.Delete(fmt.Sprintf("/oauth/clients/%v", oauthClientIdentity))
}

// Info for an OAuth client
func (s *Service) OAuthClientInfo(oauthClientIdentity string) (*OAuthClient, error) {
	var oauthClient OAuthClient
	return &oauthClient, s.Get(&oauthClient, fmt.Sprintf("/oauth/clients/%v", oauthClientIdentity), nil)
}

// List OAuth clients
func (s *Service) OAuthClientList(lr *ListRange) ([]*OAuthClient, error) {
	var oauthClientList []*OAuthClient
	return oauthClientList, s.Get(&oauthClientList, fmt.Sprintf("/oauth/clients"), lr)
}

// Update OAuth client
func (s *Service) OAuthClientUpdate(oauthClientIdentity string, o struct {
	Name        *string `json:"name,omitempty"`
	RedirectURI *string `json:"redirect_uri,omitempty"`
}) (*OAuthClient, error) {
	var oauthClient OAuthClient
	return &oauthClient, s.Patch(&oauthClient, fmt.Sprintf("/oauth/clients/%v", oauthClientIdentity), o)
}

// Plans represent different configurations of add-ons that may be added
// to apps.
type Plan struct {
	CreatedAt   time.Time `json:"created_at"`
	Default     bool      `json:"default"`
	Description string    `json:"description"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Price       struct {
		Cents int64  `json:"cents"`
		Unit  string `json:"unit"`
	} `json:"price"` // price
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Info for existing plan.
func (s *Service) PlanInfo(addonServiceIdentity string, planIdentity string) (*Plan, error) {
	var plan Plan
	return &plan, s.Get(&plan, fmt.Sprintf("/addon-services/%v/plans/%v", addonServiceIdentity, planIdentity), nil)
}

// List existing plans.
func (s *Service) PlanList(addonServiceIdentity string, lr *ListRange) ([]*Plan, error) {
	var planList []*Plan
	return planList, s.Get(&planList, fmt.Sprintf("/addon-services/%v/plans", addonServiceIdentity), lr)
}

// A slug is a snapshot of your application code that is ready to run on
// the platform.
type Slug struct {
	Blob struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"blob"` // pointer to the url where clients can fetch or store the actual
	// release binary
	BuildpackProvidedDescription *string           `json:"buildpack_provided_description"`
	Commit                       *string           `json:"commit"`
	CreatedAt                    time.Time         `json:"created_at"`
	ID                           string            `json:"id"`
	ProcessTypes                 map[string]string `json:"process_types"`
	UpdatedAt                    time.Time         `json:"updated_at"`
}

// Info for existing slug.
func (s *Service) SlugInfo(appIdentity string, slugIdentity string) (*Slug, error) {
	var slug Slug
	return &slug, s.Get(&slug, fmt.Sprintf("/apps/%v/slugs/%v", appIdentity, slugIdentity), nil)
}

// Create a new slug. For more information please refer to [Deploying
// Slugs using the Platform
// API](https://devcenter.heroku.com/articles/platform-api-deploying-slug
// s?preview=1).
func (s *Service) SlugCreate(appIdentity string, o struct {
	BuildpackProvidedDescription *string           `json:"buildpack_provided_description,omitempty"`
	Commit                       *string           `json:"commit,omitempty"`
	ProcessTypes                 map[string]string `json:"process_types"`
}) (*Slug, error) {
	var slug Slug
	return &slug, s.Post(&slug, fmt.Sprintf("/apps/%v/slugs", appIdentity), o)
}

// [SSL Endpoint](https://devcenter.heroku.com/articles/ssl-endpoint) is
// a public address serving custom SSL cert for HTTPS traffic to a
// Heroku app. Note that an app must have the `ssl:endpoint` addon
// installed before it can provision an SSL Endpoint using these APIs.
type SSLEndpoint struct {
	CertificateChain string    `json:"certificate_chain"`
	CName            string    `json:"cname"`
	CreatedAt        time.Time `json:"created_at"`
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Create a new SSL endpoint.
func (s *Service) SSLEndpointCreate(appIdentity string, o struct {
	CertificateChain string `json:"certificate_chain"`
	PrivateKey       string `json:"private_key"`
}) (*SSLEndpoint, error) {
	var sslEndpoint SSLEndpoint
	return &sslEndpoint, s.Post(&sslEndpoint, fmt.Sprintf("/apps/%v/ssl-endpoints", appIdentity), o)
}

// Delete existing SSL endpoint.
func (s *Service) SSLEndpointDelete(appIdentity string, sslEndpointIdentity string) error {
	return s.Delete(fmt.Sprintf("/apps/%v/ssl-endpoints/%v", appIdentity, sslEndpointIdentity))
}

// Info for existing SSL endpoint.
func (s *Service) SSLEndpointInfo(appIdentity string, sslEndpointIdentity string) (*SSLEndpoint, error) {
	var sslEndpoint SSLEndpoint
	return &sslEndpoint, s.Get(&sslEndpoint, fmt.Sprintf("/apps/%v/ssl-endpoints/%v", appIdentity, sslEndpointIdentity), nil)
}

// List existing SSL endpoints.
func (s *Service) SSLEndpointList(appIdentity string, lr *ListRange) ([]*SSLEndpoint, error) {
	var sslEndpointList []*SSLEndpoint
	return sslEndpointList, s.Get(&sslEndpointList, fmt.Sprintf("/apps/%v/ssl-endpoints", appIdentity), lr)
}

// Update an existing SSL endpoint.
func (s *Service) SSLEndpointUpdate(appIdentity string, sslEndpointIdentity string, o struct {
	CertificateChain *string `json:"certificate_chain,omitempty"`
	PrivateKey       *string `json:"private_key,omitempty"`
	Rollback         *bool   `json:"rollback,omitempty"`
}) (*SSLEndpoint, error) {
	var sslEndpoint SSLEndpoint
	return &sslEndpoint, s.Patch(&sslEndpoint, fmt.Sprintf("/apps/%v/ssl-endpoints/%v", appIdentity, sslEndpointIdentity), o)
}

