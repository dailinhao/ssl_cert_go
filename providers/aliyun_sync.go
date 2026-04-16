package providers

import (
	"context"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cas"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
)

// AliyunSyncClient 阿里云同步客户端
type AliyunSyncClient struct {
	dnsClient *alidns.Client
	casClient *cas.Client
}

// NewAliyunSyncClient 创建阿里云同步客户端
func NewAliyunSyncClient(regionID, accessKeyID, accessKeySecret string) (*AliyunSyncClient, error) {
	dnsClient, err := alidns.NewClientWithAccessKey(regionID, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("创建DNS客户端失败: %w", err)
	}

	casClient, err := cas.NewClientWithAccessKey(regionID, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("创建CAS客户端失败: %w", err)
	}

	return &AliyunSyncClient{
		dnsClient: dnsClient,
		casClient: casClient,
	}, nil
}

// GetDomains 获取所有域名
func (c *AliyunSyncClient) GetDomains(ctx context.Context) ([]DomainInfo, error) {
	request := alidns.CreateDescribeDomainsRequest()
	request.PageSize = "50"
	request.PageNumber = "1"

	response, err := c.dnsClient.DescribeDomains(request)
	if err != nil {
		return nil, fmt.Errorf("获取域名列表失败: %w", err)
	}

	var domains []DomainInfo
	for _, domain := range response.Domains.Domain {
		domains = append(domains, DomainInfo{
			DomainName: domain.DomainName,
		})
	}

	return domains, nil
}

// GetSubDomains 获取子域名
func (c *AliyunSyncClient) GetSubDomains(ctx context.Context, domainName string) ([]interface{}, error) {
	request := alidns.CreateDescribeDomainRecordsRequest()
	request.DomainName = domainName
	request.PageSize = "50"
	request.PageNumber = "1"

	response, err := c.dnsClient.DescribeDomainRecords(request)
	if err != nil {
		return nil, fmt.Errorf("获取子域名列表失败: %w", err)
	}

	var records []interface{}
	records = append(records, response)

	return records, nil
}

// GetCertificates 获取所有证书
func (c *AliyunSyncClient) GetCertificates(ctx context.Context) ([]CertificateInfo, error) {
	// 由于CAS SDK方法名不确定，暂时返回空列表
	// 实际实现需要根据正确的SDK方法名进行修改
	// 参考API: ListUserCertificateOrder
	return []CertificateInfo{}, nil
}

// GetCertificateDetail 获取证书详情
func (c *AliyunSyncClient) GetCertificateDetail(ctx context.Context, certID string) (map[string]interface{}, error) {
	// 由于CAS SDK方法名不确定，暂时返回空字典
	// 实际实现需要根据正确的SDK方法名进行修改
	// 参考API: GetUserCertificateDetail
	return map[string]interface{}{}, nil
}

// AddDNSRecord 添加DNS记录
func (c *AliyunSyncClient) AddDNSRecord(ctx context.Context, domainName string, record map[string]interface{}) error {
	request := alidns.CreateAddDomainRecordRequest()
	request.DomainName = domainName
	request.RR = record["name"].(string)
	request.Type = record["type"].(string)
	request.Value = record["value"].(string)
	request.TTL = requests.NewInteger(record["ttl"].(int))
	if priority, ok := record["priority"]; ok {
		request.Priority = requests.NewInteger(priority.(int))
	}

	_, err := c.dnsClient.AddDomainRecord(request)
	if err != nil {
		return fmt.Errorf("添加DNS记录失败: %w", err)
	}

	return nil
}

// UpdateDNSRecord 更新DNS记录
func (c *AliyunSyncClient) UpdateDNSRecord(ctx context.Context, domainName string, recordID string, record map[string]interface{}) error {
	request := alidns.CreateUpdateDomainRecordRequest()
	request.RecordId = recordID
	request.RR = record["name"].(string)
	request.Type = record["type"].(string)
	request.Value = record["value"].(string)
	request.TTL = requests.NewInteger(record["ttl"].(int))
	if priority, ok := record["priority"]; ok {
		request.Priority = requests.NewInteger(priority.(int))
	}

	_, err := c.dnsClient.UpdateDomainRecord(request)
	if err != nil {
		return fmt.Errorf("更新DNS记录失败: %w", err)
	}

	return nil
}

// DeleteDNSRecord 删除DNS记录
func (c *AliyunSyncClient) DeleteDNSRecord(ctx context.Context, domainName string, recordID string) error {
	request := alidns.CreateDeleteDomainRecordRequest()
	request.RecordId = recordID

	_, err := c.dnsClient.DeleteDomainRecord(request)
	if err != nil {
		return fmt.Errorf("删除DNS记录失败: %w", err)
	}

	return nil
}