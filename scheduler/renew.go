package scheduler

import (
	"log"
	"time"

	"cert-manager/config"
	"cert-manager/core"
	"cert-manager/store"
)

// RenewScheduler 续期调度器
type RenewScheduler struct {
	cm        *config.ConfigManager
	certStore *store.CertStore
	acmeClient *core.ACMEClient
}

// NewRenewScheduler 创建续期调度器
func NewRenewScheduler(cm *config.ConfigManager, certStore *store.CertStore) *RenewScheduler {
	s := &RenewScheduler{
		cm:        cm,
		certStore: certStore,
	}
	return s
}

// Start 启动调度器
func (s *RenewScheduler) Start() {
	go s.run()
}

// run 运行调度器
func (s *RenewScheduler) run() {
	ticker := time.NewTicker(24 * time.Hour) // 每24小时检查一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAndRenew()
		}
	}
}

// checkAndRenew 检查并续期证书
func (s *RenewScheduler) checkAndRenew() {
	domains := s.cm.GetAllDomains()
	for _, domain := range domains {
		if !domain.AutoRenew {
			continue
		}

		go s.renewDomain(domain)
	}
}

// RenewDomain 续期单个域名的证书（公开方法）
func (s *RenewScheduler) RenewDomain(domain *config.DomainConfig) {
	s.renewDomain(domain)
}

// renewDomain 续期单个域名的证书（内部方法）
func (s *RenewScheduler) renewDomain(domain *config.DomainConfig) {
	// 创建ACME客户端
	acmeClient, err := core.NewACMEClient(domain.SSLConfig.Email, getCAURL(domain.SSLConfig.CA))
	if err != nil {
		log.Printf("创建ACME客户端失败: %v", err)
		return
	}

	// 设置DNS提供商，使用绑定的账户ID
	if err := acmeClient.SetDNSProvider(domain.DNSProvider, domain.AccountID, s.cm); err != nil {
		log.Printf("设置DNS提供商失败: %v", err)
		return
	}

	// 获取当前证书
	cert, err := s.certStore.GetLatest(domain.ID)
	var newCert *config.Certificate

	if err != nil {
		// 没有证书，需要创建新证书
		log.Printf("域名 %s 没有证书，开始创建新证书", domain.ID)
		newCert, err = acmeClient.ObtainCertificate(domain.Domain, domain.SubDomains)
		if err != nil {
			log.Printf("创建新证书失败: %v", err)
			return
		}
	} else {
		// 检查是否需要续期
		daysLeft := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
		if daysLeft > domain.RenewDays {
			log.Printf("域名 %s 的证书还有 %d 天到期，暂不需要续期", domain.ID, daysLeft)
			return
		}

		log.Printf("开始续期域名 %s 的证书，还有 %d 天到期", domain.ID, daysLeft)

		// 续期证书
		newCert, err = acmeClient.RenewCertificate(cert)
		if err != nil {
			log.Printf("续期证书失败: %v", err)
			return
		}
	}

	// 保存新证书
	if err := s.certStore.SaveCertificate(newCert); err != nil {
		log.Printf("保存新证书失败: %v", err)
		return
	}

	log.Printf("域名 %s 的证书操作成功，新证书到期时间: %s", domain.ID, newCert.NotAfter)

	// TODO: 部署新证书到服务器
}

// getCAURL 获取CA机构的URL
func getCAURL(ca string) string {
	switch ca {
	case "letsencrypt":
		return "https://acme-v02.api.letsencrypt.org/directory"
	case "zerossl":
		return "https://acme.zerossl.com/v2/DV90"
	case "google":
		return "https://dv.acme-v02.api.pki.goog/directory"
	default:
		return "https://acme-v02.api.letsencrypt.org/directory"
	}
}
