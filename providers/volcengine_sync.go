package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// VolcengineSyncClient 火山引擎同步客户端
type VolcengineSyncClient struct {
	accessKey  string
	secretKey  string
	region     string
}

// NewVolcengineSyncClient 创建火山引擎同步客户端
func NewVolcengineSyncClient(region, accessKey, secretKey string) (*VolcengineSyncClient, error) {
	return &VolcengineSyncClient{
		accessKey: accessKey,
		secretKey: secretKey,
		region:    region,
	}, nil
}

// VolcengineListDomainsResponse 火山引擎域名列表响应
type VolcengineListDomainsResponse struct {
	ResponseMetadata struct {
		RequestId string `json:"RequestId"`
	} `json:"ResponseMetadata"`
	Result struct {
		Domains []struct {
			DomainName     string `json:"DomainName"`
			Status         string `json:"Status"`
			ExpirationDate string `json:"ExpirationDate"`
		} `json:"Domains"`
		TotalCount int `json:"TotalCount"`
		PageNumber int `json:"PageNumber"`
		PageSize   int `json:"PageSize"`
	} `json:"Result"`
}

// GetDomains 获取所有域名
func (c *VolcengineSyncClient) GetDomains(ctx context.Context) ([]DomainInfo, error) {
	// 构建请求URL
	apiURL := "https://open.volcengineapi.com"
	
	// 创建请求
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	
	// 设置请求参数
	q := req.URL.Query()
	q.Add("Action", "ListDomains")
	q.Add("Version", "2018-08-01")
	q.Add("PageSize", "50")
	q.Add("PageNumber", "1")
	req.URL.RawQuery = q.Encode()
	
	// 设置请求头
	req.Header.Set("Host", "dns.volcengineapi.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Top-Region", c.region)
	req.Header.Set("X-Top-Account-Id", "") // 留空，火山引擎会根据AccessKey自动识别
	
	// 计算签名并设置Authorization头
	authorization := c.calculateSignature(req)
	req.Header.Set("Authorization", authorization)
	
	// 发送请求
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	
	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}
	
	// 解析响应
	var volcResponse VolcengineListDomainsResponse
	if err := json.Unmarshal(body, &volcResponse); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	
	// 处理响应数据
	var domains []DomainInfo
	for _, domain := range volcResponse.Result.Domains {
		domains = append(domains, DomainInfo{
			DomainName: domain.DomainName,
			Status:     domain.Status,
			ExpiryDate: domain.ExpirationDate,
		})
	}
	
	return domains, nil
}

// calculateSignature 计算火山引擎API签名
// 参考：https://www.volcengine.com/docs/6348/69823
func (c *VolcengineSyncClient) calculateSignature(req *http.Request) string {
	// 1. 获取当前时间
	now := time.Now().UTC()
	timestamp := now.Format("2006-01-02T15:04:05Z")
	date := now.Format("20060102")
	requestId := fmt.Sprintf("%d", now.UnixNano())
	
	// 2. 添加必要的头部
	req.Header.Set("X-Top-Request-Id", requestId)
	req.Header.Set("X-Top-Timestamp", timestamp)
	req.Header.Set("X-Top-Date", date)
	req.Header.Set("X-Top-Region", c.region)
	req.Header.Set("Content-Type", "application/json")
	
	// 3. 构建规范化的请求字符串
	// 方法 + 路径 + 查询字符串 + 头部 + 签名头部 + 载荷哈希
	canonicalRequest := req.Method + "\n"
	canonicalRequest += "/\n"
	canonicalRequest += req.URL.RawQuery + "\n"
	
	// 构建头部映射，将所有头部转换为小写
	headers := make(map[string]string)
	for key, values := range req.Header {
		lowerKey := strings.ToLower(key)
		headers[lowerKey] = strings.TrimSpace(values[0])
	}
	
	// 按照字典序排序头部键
	var headerKeys []string
	for key := range headers {
		headerKeys = append(headerKeys, key)
	}
	sort.Strings(headerKeys)
	
	// 构建头部字符串和签名头部
	headerString := ""
	signedHeaders := ""
	for i, key := range headerKeys {
		headerString += key + ":" + headers[key] + "\n"
		if i > 0 {
			signedHeaders += ";"
		}
		signedHeaders += key
	}
	
	canonicalRequest += headerString
	canonicalRequest += "\n"
	canonicalRequest += signedHeaders + "\n"
	canonicalRequest += "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // 空载荷的哈希
	
	// 4. 构建签名字符串
	service := "domain"
	stringToSign := "HMAC-SHA256" + "\n"
	stringToSign += timestamp + "\n"
	stringToSign += date + "/" + c.region + "/" + service + "/aws4_request" + "\n"
	
	// 计算 canonicalRequest 的 SHA256 哈希
	h := sha256.New()
	h.Write([]byte(canonicalRequest))
	canonicalRequestHash := base64.StdEncoding.EncodeToString(h.Sum(nil))
	stringToSign += canonicalRequestHash
	
	// 5. 计算签名
	// 按照火山引擎文档，使用正确的签名算法
	signingKey := c.hmacSHA256("VOLCSTACK"+c.secretKey, date)
	signingKey = c.hmacSHA256(string(signingKey), c.region)
	signingKey = c.hmacSHA256(string(signingKey), service)
	signingKey = c.hmacSHA256(string(signingKey), "aws4_request")
	signature := base64.StdEncoding.EncodeToString(c.hmacSHA256(string(signingKey), stringToSign))
	
	// 6. 构建Authorization头
	authorization := fmt.Sprintf("VOLCSTACK %s:%s", c.accessKey, signature)
	
	return authorization
}

// hmacSHA256 计算HMAC-SHA256签名并返回原始字节数组
func (c *VolcengineSyncClient) hmacSHA256(key string, data string) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return h.Sum(nil)
}

// GetCertificates 获取所有证书
func (c *VolcengineSyncClient) GetCertificates(ctx context.Context) ([]CertificateInfo, error) {
	// 暂时返回空列表，后续可以实现证书同步
	return []CertificateInfo{}, nil
}

// VolcengineListRecordsResponse 火山引擎DNS记录列表响应
 type VolcengineListRecordsResponse struct {
	ResponseMetadata struct {
		RequestId string `json:"RequestId"`
	} `json:"ResponseMetadata"`
	Result struct {
		Records []struct {
			RecordId   string `json:"RecordId"`
			RR         string `json:"RR"`
			Type       string `json:"Type"`
			Value      string `json:"Value"`
			TTL        int    `json:"TTL"`
			Priority   int    `json:"Priority"`
			Status     string `json:"Status"`
			Line       string `json:"Line"`
		} `json:"Records"`
		TotalCount int `json:"TotalCount"`
		PageNumber int `json:"PageNumber"`
		PageSize   int `json:"PageSize"`
	} `json:"Result"`
}

// GetSubDomains 获取子域名
func (c *VolcengineSyncClient) GetSubDomains(ctx context.Context, domainName string) ([]interface{}, error) {
	// 构建请求URL
	apiURL := "https://open.volcengineapi.com"
	
	// 创建请求
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	
	// 设置请求参数
	q := req.URL.Query()
	q.Add("Action", "ListRecords")
	q.Add("Version", "2018-08-01")
	q.Add("DomainName", domainName)
	q.Add("PageSize", "50")
	q.Add("PageNumber", "1")
	req.URL.RawQuery = q.Encode()
	
	// 设置请求头
	req.Header.Set("Host", "dns.volcengineapi.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Top-Region", c.region)
	req.Header.Set("X-Top-Account-Id", "") // 留空，火山引擎会根据AccessKey自动识别
	
	// 计算签名并设置Authorization头
	authorization := c.calculateSignature(req)
	req.Header.Set("Authorization", authorization)
	
	// 发送请求
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	
	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}
	
	// 解析响应
	var volcResponse VolcengineListRecordsResponse
	if err := json.Unmarshal(body, &volcResponse); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	
	// 处理响应数据
	var records []interface{}
	records = append(records, volcResponse)
	
	return records, nil
}

// AddDNSRecord 添加DNS记录
func (c *VolcengineSyncClient) AddDNSRecord(ctx context.Context, domainName string, record map[string]interface{}) error {
	// 构建请求URL
	apiURL := "https://open.volcengineapi.com"
	
	// 创建请求
	req, err := http.NewRequest("POST", apiURL, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	
	// 设置请求参数
	q := req.URL.Query()
	q.Add("Action", "CreateRecord")
	q.Add("Version", "2018-08-01")
	q.Add("DomainName", domainName)
	q.Add("RR", record["name"].(string))
	q.Add("Type", record["type"].(string))
	q.Add("Value", record["value"].(string))
	q.Add("TTL", fmt.Sprintf("%d", record["ttl"].(int)))
	if priority, ok := record["priority"]; ok {
		q.Add("Priority", fmt.Sprintf("%d", priority.(int)))
	}
	req.URL.RawQuery = q.Encode()
	
	// 设置请求头
	req.Header.Set("Host", "dns.volcengineapi.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Top-Region", c.region)
	req.Header.Set("X-Top-Account-Id", "") // 留空，火山引擎会根据AccessKey自动识别
	
	// 计算签名并设置Authorization头
	authorization := c.calculateSignature(req)
	req.Header.Set("Authorization", authorization)
	
	// 发送请求
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	
	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}
	
	return nil
}

// UpdateDNSRecord 更新DNS记录
func (c *VolcengineSyncClient) UpdateDNSRecord(ctx context.Context, domainName string, recordID string, record map[string]interface{}) error {
	// 构建请求URL
	apiURL := "https://open.volcengineapi.com"
	
	// 创建请求
	req, err := http.NewRequest("POST", apiURL, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	
	// 设置请求参数
	q := req.URL.Query()
	q.Add("Action", "UpdateRecord")
	q.Add("Version", "2018-08-01")
	q.Add("RecordId", recordID)
	q.Add("RR", record["name"].(string))
	q.Add("Type", record["type"].(string))
	q.Add("Value", record["value"].(string))
	q.Add("TTL", fmt.Sprintf("%d", record["ttl"].(int)))
	if priority, ok := record["priority"]; ok {
		q.Add("Priority", fmt.Sprintf("%d", priority.(int)))
	}
	req.URL.RawQuery = q.Encode()
	
	// 设置请求头
	req.Header.Set("Host", "dns.volcengineapi.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Top-Region", c.region)
	req.Header.Set("X-Top-Account-Id", "") // 留空，火山引擎会根据AccessKey自动识别
	
	// 计算签名并设置Authorization头
	authorization := c.calculateSignature(req)
	req.Header.Set("Authorization", authorization)
	
	// 发送请求
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	
	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}
	
	return nil
}

// DeleteDNSRecord 删除DNS记录
func (c *VolcengineSyncClient) DeleteDNSRecord(ctx context.Context, domainName string, recordID string) error {
	// 构建请求URL
	apiURL := "https://open.volcengineapi.com"
	
	// 创建请求
	req, err := http.NewRequest("POST", apiURL, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	
	// 设置请求参数
	q := req.URL.Query()
	q.Add("Action", "DeleteRecord")
	q.Add("Version", "2018-08-01")
	q.Add("RecordId", recordID)
	req.URL.RawQuery = q.Encode()
	
	// 设置请求头
	req.Header.Set("Host", "dns.volcengineapi.com")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Top-Region", c.region)
	req.Header.Set("X-Top-Account-Id", "") // 留空，火山引擎会根据AccessKey自动识别
	
	// 计算签名并设置Authorization头
	authorization := c.calculateSignature(req)
	req.Header.Set("Authorization", authorization)
	
	// 发送请求
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	
	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}
	
	return nil
}