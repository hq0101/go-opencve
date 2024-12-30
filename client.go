package go_opencve

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type CVE struct {
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CveID       string    `json:"cve_id"`
	Title       string    `json:"title,omitempty"`
	Description string    `json:"description"`
	Metrics     Metrics   `json:"metrics"`
	Weaknesses  []string  `json:"weaknesses"`
	Vendors     []string  `json:"vendors"`
}

type Metrics struct {
	Kev            ProviderData `json:"kev"`
	Ssvc           ProviderData `json:"ssvc"`
	CvssV2_0       ProviderData `json:"cvssV2_0"`
	CvssV3_0       ProviderData `json:"cvssV3_0"`
	CvssV3_1       ProviderData `json:"cvssV3_1"`
	CvssV4_0       ProviderData `json:"cvssV4_0"`
	ThreatSeverity ProviderData `json:"threat_severity"`
}

type ProviderData struct {
	Data     interface{} `json:"data"`
	Provider *string     `json:"provider"`
}

type Organization struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Name      string    `json:"name"`
}

type OrganizationListResponse struct {
	Count    int            `json:"count"`
	Next     *string        `json:"next"`
	Previous *string        `json:"previous"`
	Results  []Organization `json:"results"`
}

type ProjectListResponse struct {
	Count    int       `json:"count"`
	Next     *string   `json:"next"`
	Previous *string   `json:"previous"`
	Results  []Project `json:"results"`
}

type Project struct {
	ID            string `json:"id"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Subscriptions struct {
		Vendors  []string    `json:"vendors"`
		Products interface{} `json:"products"`
	} `json:"subscriptions"`
}

type Client struct {
	httpClient *http.Client
	baseURL    *url.URL
	username   string
	password   string
}

func NewClient(baseURL, username, password string) (*Client, error) {
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		httpClient: http.DefaultClient,
		baseURL:    parsedBaseURL,
		username:   username,
		password:   password,
	}, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	u, err := c.baseURL.Parse(path)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if body != nil {
		err := json.NewEncoder(&buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), &buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	auth := c.username + ":" + c.password
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", "Basic "+encodedAuth)

	return req, nil
}

func (c *Client) do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, fmt.Errorf("request failed with status code %d: %s", resp.StatusCode, bodyBytes)
	}

	if v != nil {
		err := json.Unmarshal(bodyBytes, v)
		if err != nil {
			return resp, fmt.Errorf("failed to unmarshal JSON: %w, response body: %s", err, bodyBytes)
		}
	}

	return resp, nil
}

type CVEListResponse struct {
	Count    int     `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []CVE   `json:"results"`
}

func (c *Client) ListCVEs(ctx context.Context, params map[string]string) (*CVEListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := "/api/cve" + "?" + queryParams.Encode()
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response CVEListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetCVE(ctx context.Context, cveID string) (*CVE, error) {
	path := fmt.Sprintf("/api/cve/%s", cveID)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var cve CVE
	_, err = c.do(req, &cve)
	if err != nil {
		return nil, err
	}

	return &cve, nil
}

func (c *Client) ListOrganizations(ctx context.Context, params map[string]string) (*OrganizationListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := "/api/organizations" + "?" + queryParams.Encode()
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response OrganizationListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetOrganization(ctx context.Context, orgName string) (*Organization, error) {
	path := fmt.Sprintf("/api/organizations/%s", orgName)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var org Organization
	_, err = c.do(req, &org)
	if err != nil {
		return nil, err
	}

	return &org, nil
}

func (c *Client) ListProjects(ctx context.Context, orgName string, params map[string]string) (*ProjectListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := fmt.Sprintf("/api/organizations/%s/projects?%s", orgName, queryParams.Encode())
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response ProjectListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetProject(ctx context.Context, orgName, projectName string) (*Project, error) {
	path := fmt.Sprintf("/api/organizations/%s/projects/%s", orgName, projectName)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var project Project
	_, err = c.do(req, &project)
	if err != nil {
		return nil, err
	}

	return &project, nil
}

type ProjectCVEListResponse struct {
	Count    int     `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []CVE   `json:"results"`
}

func (c *Client) ListProjectCVEs(ctx context.Context, orgName, projectName string, params map[string]string) (*ProjectCVEListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := fmt.Sprintf("/api/organizations/%s/projects/%s/cve?%s", orgName, projectName, queryParams.Encode())
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response ProjectCVEListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

type Product struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Name      string    `json:"name"`
}

type ProductListResponse struct {
	Count    int       `json:"count"`
	Next     *string   `json:"next"`
	Previous *string   `json:"previous"`
	Results  []Product `json:"results"`
}

type ProductCVEListResponse struct {
	Count    int     `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []CVE   `json:"results"`
}

type Vendor struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Name      string    `json:"name"`
}

type VendorListResponse struct {
	Count    int      `json:"count"`
	Next     *string  `json:"next"`
	Previous *string  `json:"previous"`
	Results  []Vendor `json:"results"`
}

type VendorCVEListResponse struct {
	Count    int     `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []CVE   `json:"results"`
}

type Weakness struct {
	CWEID     string    `json:"cwe_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type WeaknessListResponse struct {
	Count    int        `json:"count"`
	Next     *string    `json:"next"`
	Previous *string    `json:"previous"`
	Results  []Weakness `json:"results"`
}

type WeaknessCVEListResponse struct {
	Count    int     `json:"count"`
	Next     *string `json:"next"`
	Previous *string `json:"previous"`
	Results  []CVE   `json:"results"`
}

func (c *Client) ListProducts(ctx context.Context, vendorName string, params map[string]string) (*ProductListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := fmt.Sprintf("/api/vendors/%s/products?%s", vendorName, queryParams.Encode())
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response ProductListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetProduct(ctx context.Context, vendorName, productName string) (*Product, error) {
	path := fmt.Sprintf("/api/vendors/%s/products/%s", vendorName, productName)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var product Product
	_, err = c.do(req, &product)
	if err != nil {
		return nil, err
	}

	return &product, nil
}

func (c *Client) ListProductCVEs(ctx context.Context, vendorName, productName string, params map[string]string) (*ProductCVEListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := fmt.Sprintf("/api/vendors/%s/products/%s/cve?%s", vendorName, productName, queryParams.Encode())
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response ProductCVEListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) ListVendors(ctx context.Context, params map[string]string) (*VendorListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := "/api/vendors" + "?" + queryParams.Encode()
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response VendorListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetVendor(ctx context.Context, vendorName string) (*Vendor, error) {
	path := fmt.Sprintf("/api/vendors/%s", vendorName)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var vendor Vendor
	_, err = c.do(req, &vendor)
	if err != nil {
		return nil, err
	}

	return &vendor, nil
}

func (c *Client) ListVendorCVEs(ctx context.Context, vendorName string, params map[string]string) (*VendorCVEListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := fmt.Sprintf("/api/vendors/%s/cve?%s", vendorName, queryParams.Encode())
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response VendorCVEListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) ListWeaknesses(ctx context.Context, params map[string]string) (*WeaknessListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := "/api/weaknesses" + "?" + queryParams.Encode()
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response WeaknessListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetWeakness(ctx context.Context, weaknessID string) (*Weakness, error) {
	path := fmt.Sprintf("/api/weaknesses/%s", weaknessID)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var weakness Weakness
	_, err = c.do(req, &weakness)
	if err != nil {
		return nil, err
	}

	return &weakness, nil
}

func (c *Client) ListWeaknessCVEs(ctx context.Context, weaknessID string, params map[string]string) (*WeaknessCVEListResponse, error) {
	queryParams := url.Values{}
	for k, v := range params {
		queryParams.Add(k, v)
	}

	path := fmt.Sprintf("/api/weaknesses/%s/cve?%s", weaknessID, queryParams.Encode())
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response WeaknessCVEListResponse
	_, err = c.do(req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}
