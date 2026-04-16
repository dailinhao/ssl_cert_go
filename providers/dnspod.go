// backend/providers/dnspod.go - DNSPod实现
package providers

import (
    "context"
    "encoding/json"
    "fmt"
    "net"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type DNSPodProvider struct {
    ID     string
    Token  string
    Region string // cn, global
    client *http.Client
}

func init() {
    Register("dnspod", func(config map[string]string) (DNSProvider, error) {
        return &DNSPodProvider{
            ID:     config["id"],
            Token:  config["token"],
            Region: config["region"],
            client: &http.Client{Timeout: 30 * time.Second},
        }, nil
    })
}

func (d *DNSPodProvider) Name() string {
    return "dnspod"
}

func (d *DNSPodProvider) getAPIBase() string {
    if d.Region == "cn" {
        return "https://dnsapi.cn"
    }
    return "https://api.dnspod.com"
}

func (d *DNSPodProvider) AddTXTRecord(ctx context.Context, domain, subdomain, value string, ttl int) error {
    apiURL := fmt.Sprintf("%s/Record.Create", d.getAPIBase())
    
    data := url.Values{}
    data.Set("login_token", fmt.Sprintf("%s,%s", d.ID, d.Token))
    data.Set("format", "json")
    data.Set("domain", domain)
    data.Set("sub_domain", subdomain)
    data.Set("record_type", "TXT")
    data.Set("record_line", "默认")
    data.Set("value", value)
    data.Set("ttl", fmt.Sprintf("%d", ttl))
    
    req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(data.Encode()))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("User-Agent", "CertManager/1.0")
    
    resp, err := d.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    var result struct {
        Status struct {
            Code    string `json:"code"`
            Message string `json:"message"`
        } `json:"status"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return err
    }
    
    if result.Status.Code != "1" {
        return fmt.Errorf("dnspod error: %s", result.Status.Message)
    }
    
    return nil
}

func (d *DNSPodProvider) RemoveTXTRecord(ctx context.Context, domain, subdomain string) error {
    // 先查询记录ID，然后删除
    // ... 实现类似AddTXTRecord
    return nil
}

func (d *DNSPodProvider) CheckPropagation(ctx context.Context, domain, token string) (bool, error) {
    // 使用DNS查询检查TXT记录是否生效
    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{
                Timeout: 5 * time.Second,
            }
            return d.DialContext(ctx, network, "8.8.8.8:53")
        },
    }
    
    txtRecords, err := resolver.LookupTXT(ctx, domain)
    if err != nil {
        return false, nil // 未找到不代表错误，可能还没生效
    }
    
    for _, txt := range txtRecords {
        if strings.Contains(txt, token) {
            return true, nil
        }
    }
    return false, nil
}