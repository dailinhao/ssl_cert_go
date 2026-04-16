package providers

import (
	"context"
)

// SyncClient 同步客户端接口，定义了获取域名和证书的方法
type SyncClient interface {
	// GetDomains 获取所有域名
	GetDomains(ctx context.Context) ([]DomainInfo, error)
	
	// GetSubDomains 获取子域名记录
	GetSubDomains(ctx context.Context, domainName string) ([]interface{}, error)
	
	// GetCertificates 获取所有证书
	GetCertificates(ctx context.Context) ([]CertificateInfo, error)
	
	// AddDNSRecord 添加DNS记录
	AddDNSRecord(ctx context.Context, domainName string, record map[string]interface{}) error
	
	// UpdateDNSRecord 更新DNS记录
	UpdateDNSRecord(ctx context.Context, domainName string, recordID string, record map[string]interface{}) error
	
	// DeleteDNSRecord 删除DNS记录
	DeleteDNSRecord(ctx context.Context, domainName string, recordID string) error
}

// DomainInfo 域名信息结构体
type DomainInfo struct {
	DomainName string
	Status     string
	ExpiryDate string
}

// CertificateInfo 证书信息结构体
type CertificateInfo struct {
	DomainName string
	Status     string
	ExpiryDate string
	Issuer     string
	SerialNumber string
}