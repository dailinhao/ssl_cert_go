package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"cert-manager/config"
	"cert-manager/providers"
)

// ACMEClient ACME客户端
type ACMEClient struct {
	client *lego.Client
}

// NewACMEClient 创建ACME客户端
func NewACMEClient(email string, caURL string) (*ACMEClient, error) {
	// 生成私钥
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// 创建用户
	user := &User{
		Email: email,
		Key:   privKey,
	}

	// 配置ACME客户端
	cfg := lego.NewConfig(user)
	cfg.CADirURL = caURL

	// 创建客户端
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// 注册用户
	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, err
	}

	user.Registration = reg

	return &ACMEClient{client: client}, nil
}

// User ACME用户
type User struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// SetDNSProvider 设置DNS提供商
func (ac *ACMEClient) SetDNSProvider(providerConfig config.DNSProviderConfig, accountID string, cm *config.ConfigManager) error {
	// 构建配置映射
	configMap := make(map[string]string)
	
	// 如果提供了账户ID，从账户中获取凭证
	if accountID != "" && cm != nil {
		if account, ok := cm.GetAccount(accountID); ok {
			configMap["access_key_id"] = account.AccessKey
			configMap["access_key_secret"] = account.SecretKey
			configMap["region"] = account.Region
		} else {
			// 如果账户不存在，使用DNSProvider中的凭证
			for key, value := range providerConfig.Credentials {
				configMap[key] = value
			}
		}
	} else {
		// 如果没有提供账户ID，使用DNSProvider中的凭证
		for key, value := range providerConfig.Credentials {
			configMap[key] = value
		}
	}

	// 获取DNS提供者
	dnsProvider, err := providers.GetProvider(providerConfig.Type, configMap)
	if err != nil {
		return err
	}

	// 创建一个适配器，将我们的DNSProvider接口转换为lego的challenge.Provider接口
	adapter := &dnsProviderAdapter{
		provider: dnsProvider,
	}

	// 明确使用challenge.Provider类型
	var _ challenge.Provider = adapter

	ac.client.Challenge.SetDNS01Provider(adapter)
	return nil
}

// dnsProviderAdapter 适配器，将我们的DNSProvider接口转换为lego的challenge.Provider接口
type dnsProviderAdapter struct {
	provider providers.DNSProvider
}

// Present 实现lego的challenge.Provider接口
func (a *dnsProviderAdapter) Present(domain, fqdn, value string) error {
	// 提取子域名
	subdomain := fqdn[:len(fqdn)-len(domain)-1]
	return a.provider.AddTXTRecord(context.Background(), domain, subdomain, value, 60)
}

// CleanUp 实现lego的challenge.Provider接口
func (a *dnsProviderAdapter) CleanUp(domain, fqdn, value string) error {
	// 提取子域名
	subdomain := fqdn[:len(fqdn)-len(domain)-1]
	return a.provider.RemoveTXTRecord(context.Background(), domain, subdomain)
}

// Timeout 实现lego的challenge.Provider接口
func (a *dnsProviderAdapter) Timeout() (timeout, interval time.Duration) {
	return 60 * time.Second, 5 * time.Second
}

// ObtainCertificate 获取证书
func (ac *ACMEClient) ObtainCertificate(domain string, subDomains []string) (*config.Certificate, error) {
	// 构建域名列表
	domains := []string{domain}
	domains = append(domains, subDomains...)

	// 获取证书
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	cert, err := ac.client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	// 解析证书
	x509Cert, err := x509.ParseCertificate(cert.Certificate)
	if err != nil {
		return nil, err
	}

	// 构建证书记录
	certRecord := &config.Certificate{
		ID:           fmt.Sprintf("%s-%s", domain, x509Cert.SerialNumber),
		DomainID:     domain,
		Domain:       domain,
		CertPEM:      string(cert.Certificate),
		KeyPEM:       string(cert.PrivateKey),
		Issuer:       x509Cert.Issuer.CommonName,
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		SerialNumber: x509Cert.SerialNumber.String(),
		Status:       "active",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return certRecord, nil
}

// RenewCertificate 续期证书
func (ac *ACMEClient) RenewCertificate(cert *config.Certificate) (*config.Certificate, error) {
	// 解析现有证书
	_, err := x509.ParseCertificate([]byte(cert.CertPEM))
	if err != nil {
		return nil, err
	}

	// 续期
	renewed, err := ac.client.Certificate.Renew(certificate.Resource{
		Certificate: []byte(cert.CertPEM),
		PrivateKey:  []byte(cert.KeyPEM),
	}, true, false, "")
	if err != nil {
		return nil, err
	}

	// 解析续期后的证书
	x509Cert, err := x509.ParseCertificate(renewed.Certificate)
	if err != nil {
		return nil, err
	}

	// 构建证书记录
	certRecord := &config.Certificate{
		ID:           fmt.Sprintf("%s-%s", cert.Domain, x509Cert.SerialNumber),
		DomainID:     cert.DomainID,
		Domain:       cert.Domain,
		CertPEM:      string(renewed.Certificate),
		KeyPEM:       string(renewed.PrivateKey),
		Issuer:       x509Cert.Issuer.CommonName,
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		SerialNumber: x509Cert.SerialNumber.String(),
		Status:       "active",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return certRecord, nil
}

// RevokeCertificate 吊销证书
func (ac *ACMEClient) RevokeCertificate(cert *config.Certificate) error {
	return ac.client.Certificate.Revoke([]byte(cert.CertPEM))
}
