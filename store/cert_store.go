package store

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cert-manager/config"
)

// CertStore 证书存储
type CertStore struct {
	baseDir string
}

// NewCertStore 创建证书存储
func NewCertStore(baseDir string) *CertStore {
	if baseDir == "" {
		baseDir = "certs"
	}
	os.MkdirAll(baseDir, 0755)
	return &CertStore{baseDir: baseDir}
}

// SaveCertificate 保存证书
func (cs *CertStore) SaveCertificate(cert *config.Certificate) error {
	domainDir := filepath.Join(cs.baseDir, cert.DomainID)
	os.MkdirAll(domainDir, 0755)

	// 保存证书文件
	certFile := filepath.Join(domainDir, fmt.Sprintf("%s.crt", cert.SerialNumber))
	if err := os.WriteFile(certFile, []byte(cert.CertPEM), 0644); err != nil {
		return err
	}

	// 保存私钥文件
	keyFile := filepath.Join(domainDir, fmt.Sprintf("%s.key", cert.SerialNumber))
	if err := os.WriteFile(keyFile, []byte(cert.KeyPEM), 0600); err != nil {
		return err
	}

	return nil
}

// GetLatest 获取最新证书
func (cs *CertStore) GetLatest(domainID string) (*config.Certificate, error) {
	domainDir := filepath.Join(cs.baseDir, domainID)
	files, err := os.ReadDir(domainDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no certificates found for domain %s", domainID)
		}
		return nil, err
	}

	var latestCert *config.Certificate
	var latestTime time.Time

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".crt" {
			continue
		}

		certFile := filepath.Join(domainDir, file.Name())
		content, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}

		// 解析证书，处理多个证书块
		var x509Cert *x509.Certificate
		var remaining = content
		for {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					// 尝试找到服务器证书（通常是第一个）
					if x509Cert == nil {
						x509Cert = cert
					}
				}
			}
			remaining = rest
		}

		if x509Cert == nil {
			continue
		}

		// 创建证书对象
		currentCert := &config.Certificate{
			ID:           fmt.Sprintf("%s-%s", domainID, x509Cert.SerialNumber),
			DomainID:     domainID,
			Domain:       x509Cert.Subject.CommonName,
			CertPEM:      string(content),
			Issuer:       x509Cert.Issuer.CommonName,
			NotBefore:    x509Cert.NotBefore,
			NotAfter:     x509Cert.NotAfter,
			SerialNumber: x509Cert.SerialNumber.String(),
			Status:       getCertStatus(x509Cert),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// 读取对应私钥
		baseName := filepath.Base(certFile)
		ext := filepath.Ext(baseName)
		nameWithoutExt := strings.TrimSuffix(baseName, ext)
		keyFile := filepath.Join(domainDir, nameWithoutExt + ".key")
		keyContent, err := os.ReadFile(keyFile)
		if err == nil {
			currentCert.KeyPEM = string(keyContent)
		}

		// 检查是否是最新的证书
		if currentCert.NotAfter.After(latestTime) {
			latestTime = currentCert.NotAfter
			latestCert = currentCert
		}
	}

	if latestCert == nil {
		return nil, fmt.Errorf("no valid certificates found for domain %s", domainID)
	}

	return latestCert, nil
}

// GetAll 获取所有证书
func (cs *CertStore) GetAll(domainID string) ([]*config.Certificate, error) {
	domainDir := filepath.Join(cs.baseDir, domainID)
	files, err := os.ReadDir(domainDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*config.Certificate{}, nil
		}
		return nil, err
	}

	var certs []*config.Certificate

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".crt" {
			continue
		}

		certFile := filepath.Join(domainDir, file.Name())
		content, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}

		// 解析证书，处理多个证书块
		var x509Cert *x509.Certificate
		var remaining = content
		for {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					// 尝试找到服务器证书（通常是第一个）
					if x509Cert == nil {
						x509Cert = cert
					}
				}
			}
			remaining = rest
		}

		if x509Cert == nil {
			continue
		}

		cert := &config.Certificate{
			ID:           fmt.Sprintf("%s-%s", domainID, x509Cert.SerialNumber),
			DomainID:     domainID,
			Domain:       x509Cert.Subject.CommonName,
			CertPEM:      string(content),
			Issuer:       x509Cert.Issuer.CommonName,
			NotBefore:    x509Cert.NotBefore,
			NotAfter:     x509Cert.NotAfter,
			SerialNumber: x509Cert.SerialNumber.String(),
			Status:       getCertStatus(x509Cert),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// 读取对应私钥
		baseName := filepath.Base(certFile)
		ext := filepath.Ext(baseName)
		nameWithoutExt := strings.TrimSuffix(baseName, ext)
		keyFile := filepath.Join(domainDir, nameWithoutExt + ".key")
		keyContent, err := os.ReadFile(keyFile)
		if err == nil {
			cert.KeyPEM = string(keyContent)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// getCertStatus 获取证书状态
func getCertStatus(cert *x509.Certificate) string {
	now := time.Now()
	if now.After(cert.NotAfter) {
		return "expired"
	}
	if now.Before(cert.NotBefore) {
		return "not_yet_valid"
	}
	return "active"
}

// isCertValidForDomain 检查证书是否对指定域名有效
func isCertValidForDomain(cert *x509.Certificate, domain string) bool {
	// 检查CN是否匹配
	if cert.Subject.CommonName == domain {
		return true
	}
	
	// 检查CN是否是通配符
	if strings.HasPrefix(cert.Subject.CommonName, "*") {
		wildcardDomain := strings.TrimPrefix(cert.Subject.CommonName, "*")
		if strings.HasSuffix(domain, wildcardDomain) {
			return true
		}
	}
	
	// 检查SAN字段
	for _, san := range cert.DNSNames {
		if san == domain {
			return true
		}
		if strings.HasPrefix(san, "*") {
			wildcardDomain := strings.TrimPrefix(san, "*")
			if strings.HasSuffix(domain, wildcardDomain) {
				return true
			}
		}
	}
	
	return false
}
