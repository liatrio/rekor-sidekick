package opensearch

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/nsmith5/rekor-sidekick/outputs"
	"github.com/nsmith5/rekor-sidekick/rekor"

	opensearch "github.com/opensearch-project/opensearch-go"
	opensearchapi "github.com/opensearch-project/opensearch-go/opensearchapi"
)

const addAttestation = true

const (
	driverName = `opensearch`
)

type config struct {
	Severity string
	Server   string
	Insecure bool
	Index    string
	Username string
	Password string
}

type driver struct {
	index string

	client *opensearch.Client
}

// Flatten the event and create a reader
// ALSO returns the id (URL) as a string
func searchify(e rekor.LogEntry) (*strings.Reader, string, error) {
	// Struct -> map[string]interface{}
	data, err := json.Marshal(e)
	if err != nil {
		return nil, "", err
	}

	var entry map[string]interface{}
	json.Unmarshal(data, &entry)

	url := entry["URL"].(string)
	slice := strings.Split(url, "/")
	entryId := slice[len(slice)-1]

	// Optional, add the real attestation data
	if addAttestation {
		realdata, err := getAttestation(url)
		if err == nil {
			entry["attestation"] = realdata
		}
	}

	b, err := json.Marshal(entry)
	if err != nil {
		return nil, "", err
	}

	return strings.NewReader(string(b)), entryId, nil
}

func getAttestation(url string) (map[string]interface{}, error) {

	// TODO: This is really the rekor client,
	// but I don't want to redo the plumbing
	client := &http.Client{}
	req, err := http.NewRequest(`GET`, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(`Accept`, `application/json`)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// No such entry? This shouldn't happen.
	if resp.StatusCode == http.StatusNotFound {
		return nil, rekor.ErrEntryDoesntExist
	}

	// Extract the base64 decoded body.
	// Json decode -> base64 decode
	entryMap := make(map[string]interface{})

	err = json.NewDecoder(resp.Body).Decode(&entryMap)
	if err != nil {
		return nil, err
	}

	// There's only one entry, but we don't know what it is
	// We want: uuid.attestation.data | @base64d
	for _, v := range entryMap {
		// uuid.attestation
		body := v.(map[string]interface{})
		attestation, ok := body["attestation"]
		if !ok {
			return nil, fmt.Errorf("no attestation in body")
		}

		// uuid.attestation.data
		data, ok := attestation.(map[string]interface{})["data"]
		if !ok {
			return nil, fmt.Errorf("no data in the attestation")
		}

		// uuid.attestation.data | @base64d
		datab64 := data.(string)
		sDec, err := base64.StdEncoding.DecodeString(datab64)
		if err != nil {
			return nil, err
		}

		var unpacked map[string]interface{}
		json.Unmarshal(sDec, &unpacked)

		// Done!
		return unpacked, nil
	}
	return nil, fmt.Errorf("empty map")
}

func (d *driver) Send(e outputs.Event) error {

	document, id, err := searchify(e.Entry)
	if err != nil {
		return err
	}

	req := opensearchapi.IndexRequest{
		Index:      d.index,
		DocumentID: id,
		Body:       document,
	}
	res, err := req.Do(context.Background(), d.client)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func (d *driver) Name() string {
	return driverName
}

func createDriver(conf map[string]interface{}) (outputs.Output, error) {
	var c config
	err := mapstructure.Decode(conf, &c)
	if err != nil {
		return nil, err
	}

	if c.Server == "" {
		return nil, errors.New(`opensearch: server url required (e.g. https://localhost:9200)`)
	}
	if c.Index == "" {
		return nil, errors.New(`opensearch: index required (will be created if doesn't exist)`)
	}
	if c.Username == "" {
		return nil, errors.New(`opensearch: username required`)
	}
	if c.Password == "" {
		return nil, errors.New(`opensearch: password required`)
	}

	// Optional insecure flag
	var transport *http.Transport
	if c.Insecure {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	client, err := opensearch.NewClient(opensearch.Config{
		Transport: transport,
		Addresses: []string{c.Server},
		Username:  c.Username,
		Password:  c.Password,
	})

	if err != nil {
		return nil, fmt.Errorf("opensearch: failed to create client: %s", err.Error())
	}

	return &driver{
		index:  c.Index,
		client: client,
	}, nil
}

func init() {
	outputs.RegisterDriver(driverName, outputs.CreatorFunc(createDriver))
}
