package rdns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	contentType     = "Content-Type"
	jsonContentType = "application/json"
	secretKey       = "rdns-token"
	cnamePath       = "/cname"
)

func jsonBody(payload interface{}) (io.Reader, error) {
	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(payload)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

type Client struct {
	httpClient *http.Client
	base       string
	lock       *sync.RWMutex
	namespace  string
}

func (c *Client) request(method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(contentType, jsonContentType)

	return req, nil
}

func (c *Client) do(req *http.Request) (Response, error) {
	var data Response
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return data, err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, errors.Wrap(err, "read response body error")
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return data, errors.Wrapf(err, "decode response error: %s", string(body))
	}
	logrus.Debugf("got response entry: %+v", data)
	if code := resp.StatusCode; code < 200 || code > 300 {
		if data.Message != "" {
			return data, errors.Errorf("got request error: %s", data.Message)
		}
	}

	return data, nil
}

func (c *Client) ApplyDomain(hosts []string, subDomain map[string][]string, cname bool) (bool, string, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	d, err := c.GetDomain(cname)
	if err != nil {
		return false, "", err
	}

	if d == nil {
		logrus.Debugf("fqdn configuration does not exist, need to create a new one")
		fqdn, err := c.CreateDomain(hosts, cname)
		return true, fqdn, err
	}

	sort.Strings(d.Hosts)
	sort.Strings(hosts)
	if !reflect.DeepEqual(d.Hosts, hosts) || !reflect.DeepEqual(d.SubDomain, subDomain) {
		logrus.Debugf("fqdn %s or subdomains %+v has some changes, need to update", d.Fqdn, d.SubDomain)
		fqdn, err := c.UpdateDomain(hosts, subDomain, cname)
		return false, fqdn, err
	}
	logrus.Debugf("fqdn %s has no changes, no need to update", d.Fqdn)
	fqdn, _, _ := c.getSecret()

	return false, fqdn, nil
}

func (c *Client) GetDomain(cname bool) (d *Domain, err error) {
	fqdn, token, err := c.getSecret()
	if err != nil {
		return nil, errors.Wrap(err, "GetDomain: failed to get stored secret")
	}

	if fqdn == "" || token == "" {
		return nil, nil
	}

	path := ""
	if cname {
		path = cnamePath
	}
	url := buildURL(c.base, "/"+fqdn, path)
	req, err := c.request(http.MethodGet, url, nil)
	if err != nil {
		return d, errors.Wrap(err, "GetDomain: failed to build a request")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	o, err := c.do(req)
	if err != nil {
		return d, errors.Wrap(err, "GetDomain: failed to execute a request")
	}

	if o.Data.Fqdn == "" {
		return nil, nil
	}

	return &o.Data, nil
}

func (c *Client) CreateDomain(hosts []string, cname bool) (string, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	path := ""
	options := &DomainOptions{}
	if cname {
		options.CNAME = hosts[0]
		path = cnamePath
	} else {
		options.Hosts = hosts
	}
	url := buildURL(c.base, "", path)
	body, err := jsonBody(options)
	if err != nil {
		return "", err
	}

	req, err := c.request(http.MethodPost, url, body)
	if err != nil {
		return "", errors.Wrap(err, "CreateDomain: failed to build a request")
	}

	resp, err := c.do(req)
	if err != nil {
		return "", errors.Wrap(err, "CreateDomain: failed to execute a request")
	}

	if err = c.setSecret(&resp); err != nil {
		return "", err
	}

	return resp.Data.Fqdn, err
}

func (c *Client) UpdateDomain(hosts []string, subDomain map[string][]string, cname bool) (string, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	fqdn, token, err := c.getSecret()
	if err != nil {
		return "", errors.Wrap(err, "UpdateDomain: failed to get stored secret")
	}

	path := ""
	options := &DomainOptions{
		SubDomain: subDomain,
	}
	if cname {
		options.CNAME = hosts[0]
		path = cnamePath
	} else {
		options.Hosts = hosts
	}

	url := buildURL(c.base, "/"+fqdn, path)
	body, err := jsonBody(options)
	if err != nil {
		return "", err
	}

	req, err := c.request(http.MethodPut, url, body)
	if err != nil {
		return "", errors.Wrap(err, "UpdateDomain: failed to build a request")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	_, err = c.do(req)
	if err != nil {
		return "", errors.Wrap(err, "UpdateDomain: failed to execute a request")
	}

	return fqdn, nil
}

func (c *Client) DeleteDomain() (string, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	fqdn, token, err := c.getSecret()
	if err != nil {
		return "", errors.Wrap(err, "DeleteDomain: failed to get stored secret")
	}

	url := buildURL(c.base, "/"+fqdn, "")
	req, err := c.request(http.MethodDelete, url, nil)
	if err != nil {
		return "", errors.Wrap(err, "DeleteDomain: failed to build a request")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	_, err = c.do(req)
	if err != nil {
		return "", errors.Wrap(err, "DeleteDomain: failed to execute a request")
	}

	return fqdn, err
}

func (c *Client) RenewDomain() (string, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	fqdn, token, err := c.getSecret()
	if err != nil {
		return "", errors.Wrap(err, "RenewDomain: failed to get stored secret")
	}

	url := buildURL(c.base, "/"+fqdn, "/renew")
	req, err := c.request(http.MethodPut, url, nil)
	if err != nil {
		return "", errors.Wrap(err, "RenewDomain: failed to build a request")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	_, err = c.do(req)
	if err != nil {
		return "", errors.Wrap(err, "RenewDomain: failed to execute a request")
	}

	return fqdn, err
}

func (c *Client) SetBaseURL(base string) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if base != c.base {
		c.base = base
	}
}

func (c *Client) setSecret(resp *Response) error {
	token := resp.Token
	fqdn := resp.Data.Fqdn

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(homeDir, ".tunnelware"), 0755); err != nil {
		return err
	}

	fqdnFile := filepath.Join(homeDir, ".tunnelware", ".fqdn")
	tokenFile := filepath.Join(homeDir, ".tunnelware", ".tokenFile")

	if err := ioutil.WriteFile(tokenFile, []byte(token), 0755); err != nil {
		return err
	}

	if err := ioutil.WriteFile(fqdnFile, []byte(fqdn), 0755); err != nil {
		return err
	}

	return nil
}

//getSecret return token and fqdn
func (c *Client) getSecret() (string, string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	rdnsFile := filepath.Join(homeDir, ".tunnelware", ".fqdn")
	tokenFile := filepath.Join(homeDir, ".tunnelware", ".tokenFile")
	domain, err := ioutil.ReadFile(rdnsFile)
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	token, err := ioutil.ReadFile(tokenFile)
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	return string(domain), string(token), nil
}

func NewClient() *Client {
	return &Client{
		httpClient: http.DefaultClient,
		lock:       &sync.RWMutex{},
		base:       "https://api.on-rio.io/v1",
	}
}

//buildUrl return request url
func buildURL(base, fqdn, path string) (url string) {
	return fmt.Sprintf("%s/domain%s%s", base, fqdn, path)
}
