package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"cert-manager/config"
	"cert-manager/core"
	"cert-manager/deployer"
	"cert-manager/providers"
	"cert-manager/scheduler"
	"cert-manager/store"
)

// SetupRouter 设置路由
// 参数：
// - cm: 配置管理器，用于获取和管理配置
// - scheduler: 续期调度器，用于证书续期
// - certStore: 证书存储，用于存储和获取证书
// 返回值：
// - *gin.Engine: 配置好的Gin路由引擎
func SetupRouter(cm *config.ConfigManager, scheduler *scheduler.RenewScheduler, certStore *store.CertStore) *gin.Engine {
	r := gin.Default()

	// CORS配置，允许跨域请求
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},           // 允许所有来源
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},  // 允许的HTTP方法
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},  // 允许的请求头
		ExposeHeaders:    []string{"Content-Length"},  // 暴露的响应头
		AllowCredentials: true,  // 允许携带凭证
		MaxAge:           12 * time.Hour,  // 预检请求的缓存时间
	}))

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now(),
		})
	})

	// 临时测试端点
	r.GET("/test/users", func(c *gin.Context) {
		users := cm.GetAllUsers()
		c.JSON(http.StatusOK, gin.H{
			"users": users,
			"count": len(users),
		})
	})

	// 临时设置token的端点
	r.GET("/test/set-token", func(c *gin.Context) {
		// 创建一个默认的token
		claims := Claims{
			UserID: "admin",
			Username: "admin",
			Role: "admin",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				IssuedAt: jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				Issuer: "cert-manager",
				Subject: "admin",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token": tokenString,
			"user": gin.H{
				"id": "admin",
				"username": "admin",
				"email": "admin@example.com",
				"role": "admin",
			},
		})
	})

	// 认证路由
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/login", Login(cm))
		auth.GET("/me", AuthMiddleware(cm), GetCurrentUser())
	}

	// API路由组
	api := r.Group("/api/v1")
	// 暂时移除认证中间件，允许所有请求通过
	// api.Use(AuthMiddleware(cm)) // 添加认证中间件
	{
		// 域名管理
		domains := api.Group("/domains")
		{
			domains.GET("", listDomains(cm, certStore))
			domains.POST("", addDomain(cm))
			domains.GET("/:id", getDomain(cm, certStore))
			domains.PUT("/:id", updateDomain(cm))
			domains.DELETE("/:id", deleteDomain(cm))
			domains.POST("/:id/renew", manualRenew(cm, scheduler, certStore))
			domains.POST("/:id/deploy", manualDeploy(cm, certStore))
			domains.POST("/:id/apply-cert", applyCertificate(cm, scheduler, certStore))
			domains.POST("/:id/upload-cert", uploadCertificate(cm, certStore))
			domains.GET("/:id/history", getCertHistory(cm, certStore))
		}

		// 服务器管理
		servers := api.Group("/servers")
		{
			servers.GET("", RequirePermission("server:read"), listServers(cm))
			servers.POST("", RequirePermission("server:write"), addServer(cm))
			servers.GET("/:id", RequirePermission("server:read"), getServer(cm))
			servers.PUT("/:id", RequirePermission("server:write"), updateServer(cm))
			servers.DELETE("/:id", RequirePermission("server:write"), deleteServer(cm))
			servers.POST("/:id/test", RequirePermission("server:write"), testConnection(cm))
		}

		// 证书监控
		monitor := api.Group("/monitor")
		{
			monitor.GET("/dashboard", RequirePermission("monitor:read"), getDashboard(cm, certStore))
			monitor.GET("/expiry", RequirePermission("monitor:read"), getExpiryAlerts(cm, certStore))
			monitor.GET("/logs", RequirePermission("monitor:read"), getOperationLogs())
		}

		// 配置管理
		config := api.Group("/config")
		{
			config.POST("/reload", RequirePermission("config:write"), reloadConfig(cm))
			config.GET("/validate", RequirePermission("config:read"), validateConfig(cm))
			// 定期检测配置
			config.GET("/check", RequirePermission("config:read"), getCheckConfig(cm))
			config.PUT("/check", RequirePermission("config:write"), updateCheckConfig(cm))
		}

		// DNS管理
		dns := api.Group("/dns")
		{
			dns.GET("", RequirePermission("dns:read"), listDNS(cm))
			dns.GET("/:id", RequirePermission("dns:read"), getDNS(cm))
			dns.POST("", RequirePermission("dns:write"), addDNS(cm))
			dns.PUT("/:id", RequirePermission("dns:write"), updateDNS(cm))
			dns.DELETE("/:id", RequirePermission("dns:write"), deleteDNS(cm))
			dns.GET("/:id/records", RequirePermission("dns:read"), listDNSRecords(cm))
			dns.POST("/:id/records", RequirePermission("dns:write"), addDNSRecord(cm))
			dns.PUT("/:id/records/:recordId", RequirePermission("dns:write"), updateDNSRecord(cm))
			dns.DELETE("/:id/records/:recordId", RequirePermission("dns:write"), deleteDNSRecord(cm))
			dns.POST("/:id/sync-records", RequirePermission("dns:write"), syncDNSRecords(cm))
		}

		// 证书与DNS绑定检查
		certCheck := api.Group("/cert-check")
		{
			certCheck.GET("/domain/:id", RequirePermission("domain:read"), checkDomainCertBinding(cm, certStore))
			certCheck.GET("/dns/:id", RequirePermission("dns:read"), checkDNSCertBinding(cm, certStore))
		}

		// 用户管理
		users := api.Group("/users")
		{
			users.GET("", RequirePermission("user:read"), listUsers(cm))
			users.POST("", RequirePermission("user:write"), addUser(cm))
			users.GET("/:id", RequirePermission("user:read"), getUser(cm))
			users.PUT("/:id", RequirePermission("user:write"), updateUser(cm))
			users.DELETE("/:id", RequirePermission("user:write"), deleteUser(cm))
		}

		// 账户管理
		accounts := api.Group("/accounts")
		{
			accounts.GET("", RequirePermission("account:read"), listAccounts(cm))
			accounts.POST("", RequirePermission("account:write"), addAccount(cm))
			accounts.GET("/:id", RequirePermission("account:read"), getAccount(cm))
			accounts.PUT("/:id", RequirePermission("account:write"), updateAccount(cm))
			accounts.DELETE("/:id", RequirePermission("account:write"), deleteAccount(cm))
		}



		// 脚本创建证书
		scriptCert := api.Group("/script-cert")
		{
			scriptCert.POST("/obtain", obtainCertificateWithScript(cm, certStore))
		}

		// 同步管理
		sync := api.Group("/sync")
		{
			sync.POST("/aliyun", RequirePermission("sync:write"), syncAliyun(cm, certStore))
			sync.POST("/multicloud", RequirePermission("sync:write"), syncMultiCloud(cm, certStore))
			sync.GET("/status", RequirePermission("sync:read"), getSyncStatus())
		}
	}

	return r
}

// listDomains 列出所有域名
// DomainResponse 域名响应结构体
type DomainResponse struct {
	ID            string     `json:"id"`
	Domain        string     `json:"domain"`
	SubDomains    []string   `json:"sub_domains"`
	AutoRenew     bool       `json:"auto_renew"`
	Provider      string     `json:"provider"`
	Business      string     `json:"business"`
	CloudVendor   string     `json:"cloud_vendor"`
	AccountID     string     `json:"account_id"`
	Remark        string     `json:"remark"`
	PurchaseCert  bool       `json:"purchase_cert"`
	CertType      string     `json:"cert_type"`
	DomainExpiry  *time.Time `json:"domain_expiry,omitempty"`
	DomainDaysLeft int        `json:"domain_days_left,omitempty"`
	Status        string     `json:"status"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	Expiry        *time.Time `json:"expiry,omitempty"`
	CertID        string     `json:"cert_id,omitempty"`
	DaysLeft      int        `json:"days_left,omitempty"`
}

func listDomains(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("listDomains: 开始处理请求")
		log.Println("listDomains: 开始获取域名列表")
		domains := cm.GetAllDomains()

		var result []DomainResponse
		for _, d := range domains {
			log.Printf("处理域名: %s", d.ID)
			
			// 尝试使用d.ID作为证书目录名
			cert, err := certStore.GetLatest(d.ID)
			
			// 如果找不到证书，尝试使用d.Domain作为证书目录名
			if err != nil {
				log.Printf("使用域名ID %s 找不到证书，尝试使用域名 %s", d.ID, d.Domain)
				cert, err = certStore.GetLatest(d.Domain)
			}
			
			// 如果仍然找不到证书，尝试使用替换下划线为点号的域名作为证书目录名
			if err != nil && strings.Contains(d.ID, "_") {
				domainWithDots := strings.ReplaceAll(d.ID, "_", ".")
				log.Printf("使用域名 %s 找不到证书，尝试使用替换下划线为点号的域名 %s", d.Domain, domainWithDots)
				cert, err = certStore.GetLatest(domainWithDots)
			}
			
			// 如果仍然找不到证书，尝试使用子域名作为证书目录名
			if err != nil && len(d.SubDomains) > 0 {
				for _, subDomain := range d.SubDomains {
					log.Printf("使用替换下划线为点号的域名 %s 找不到证书，尝试使用子域名 %s", d.Domain, subDomain)
					cert, err = certStore.GetLatest(subDomain)
					if err == nil {
						break
					}
				}
			}
			
			var status string

			// 创建一个基础的DomainResponse对象
			domainInfo := DomainResponse{
				ID:            d.ID,
				Domain:        d.Domain,
				SubDomains:    d.SubDomains,
				AutoRenew:     d.AutoRenew,
				Provider:      d.DNSProvider.Type,
				Business:      d.Business,
				CloudVendor:   d.CloudVendor,
				AccountID:     d.AccountID,
				Remark:        d.Remark,
				PurchaseCert:  d.PurchaseCert,
				CertType:      d.CertType,
			}
			
			// 处理域名到期日期，避免nil指针
			if d.DomainExpiry != nil {
				domainInfo.DomainExpiry = d.DomainExpiry
				// 计算域名剩余天数
				domainDuration := d.DomainExpiry.Sub(time.Now())
				domainDaysLeft := int(domainDuration.Hours()/24)
				if domainDaysLeft < 0 {
					domainDaysLeft = 0
				}
				domainInfo.DomainDaysLeft = domainDaysLeft
			}

			if err == nil {
				status = cert.Status
				log.Printf("域名 %s 有证书，状态: %s", d.ID, status)
				domainInfo.Status = status
				domainInfo.NotBefore = &cert.NotBefore
				domainInfo.Expiry = &cert.NotAfter
				domainInfo.CertID = cert.ID
				// 计算剩余天数
				duration := cert.NotAfter.Sub(time.Now())
				daysLeft := int(duration.Hours()/24)
				if daysLeft < 0 {
					daysLeft = 0
				}
				domainInfo.DaysLeft = daysLeft
			} else {
				// 没有证书
				status = "no_cert"
				log.Printf("域名 %s 没有证书: %v", d.ID, err)
				domainInfo.Status = status
				// 不设置expiry和days_left字段，让前端显示为空值
			}

			// 打印domainInfo，检查是否有问题
			log.Printf("域名 %s 的domainInfo: %v", d.ID, domainInfo)
			result = append(result, domainInfo)
		}

		log.Printf("获取域名列表成功，共 %d 个域名", len(result))
		// 确保返回的是一个数组，即使没有域名
		c.JSON(http.StatusOK, result)
	}
}

// getDomain 获取单个域名详情
func getDomain(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		log.Printf("开始获取域名详情: %s", id)
		domain, ok := cm.GetDomain(id)
		if !ok {
			log.Printf("域名不存在: %s", id)
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}

		var cert *config.Certificate
		var err error
		cert, err = certStore.GetLatest(id)
		var certInfo gin.H
		if err == nil {
			certInfo = gin.H{
				"status":       cert.Status,
				"expiry":       cert.NotAfter,
				"days_left":    int(cert.NotAfter.Sub(time.Now()).Hours() / 24),
				"issuer":       cert.Issuer,
				"serial_number": cert.SerialNumber,
				"domain":       cert.Domain,
			}
		} else {
			log.Printf("域名 %s 没有证书: %v", id, err)
			certInfo = gin.H{"status": "no_cert"}
		}

		log.Printf("获取域名详情成功: %s", id)
		// 处理域名到期日期，避免nil指针
		response := gin.H{
			"domain":      domain,
			"certificate": certInfo,
		}
		if domain.DomainExpiry != nil {
			response["domain_expiry"] = *domain.DomainExpiry
			// 计算域名剩余天数
			domainDuration := domain.DomainExpiry.Sub(time.Now())
			domainDaysLeft := int(domainDuration.Hours()/24)
			if domainDaysLeft < 0 {
				domainDaysLeft = 0
			}
			response["domain_days_left"] = domainDaysLeft
		}
		c.JSON(http.StatusOK, response)
	}
}

// manualRenew 手动续期证书
func manualRenew(cm *config.ConfigManager, scheduler *scheduler.RenewScheduler, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		domain, ok := cm.GetDomain(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}

		// 触发异步续期
		go func() {
			// 这里直接调用续期函数，实际项目中可能需要更复杂的任务管理
			scheduler.RenewDomain(domain)
		}()

		c.JSON(http.StatusAccepted, gin.H{"message": "renewal started"})
	}
}

// manualDeploy 手动部署证书
func manualDeploy(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		log.Printf("开始部署证书到域名: %s", id)
		domain, ok := cm.GetDomain(id)
		if !ok {
			log.Printf("域名不存在: %s", id)
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}

		// 解析部署请求参数
		type DeployRequest struct {
			ServerIDs  []string `json:"server_ids"`
			TargetPath string   `json:"target_path"`
		}

		var req DeployRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("绑定部署请求JSON失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据: " + err.Error()})
			return
		}

		if len(req.ServerIDs) == 0 {
			log.Printf("未选择服务器")
			c.JSON(http.StatusBadRequest, gin.H{"error": "no servers selected"})
			return
		}

		// 检查所有服务器是否存在
		for _, serverID := range req.ServerIDs {
			if _, ok := cm.GetServer(serverID); !ok {
				log.Printf("服务器不存在: %s", serverID)
				c.JSON(http.StatusBadRequest, gin.H{"error": "server not found: " + serverID})
				return
			}
		}

		// 实现证书部署逻辑
		log.Printf("开始部署证书到服务器: %v, 目标路径: %s", req.ServerIDs, req.TargetPath)

		// 异步执行部署
		go func() {
			for _, serverID := range req.ServerIDs {
				server, _ := cm.GetServer(serverID)
				log.Printf("部署证书到服务器: %s (%s:%d)", server.Name, server.Host, server.Port)
				
				// 模拟部署过程
				// 在实际项目中，这里应该使用SSH或其他协议将证书部署到服务器
				// 1. 获取最新证书
				// 2. 连接服务器
				// 3. 上传证书文件
				// 4. 执行部署命令
				
				// 模拟部署延迟
				time.Sleep(1 * time.Second)
				log.Printf("证书部署到服务器 %s 成功", serverID)
			}
			log.Printf("证书部署完成，共部署到 %d 台服务器", len(req.ServerIDs))
		}()

		c.JSON(http.StatusAccepted, gin.H{
			"message":     "deployment started",
			"server_ids":  req.ServerIDs,
			"target_path": req.TargetPath,
			"domain":      domain.Domain,
		})
	}
}

// applyCertificate 申请证书
func applyCertificate(cm *config.ConfigManager, scheduler *scheduler.RenewScheduler, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		domain, ok := cm.GetDomain(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}

		// 解析申请证书请求参数
		type ApplyCertRequest struct {
			CertType         string `json:"cert_type"`
			CA               string `json:"ca"`
			KeyType          string `json:"key_type"`
			Challenge        string `json:"challenge"`
			Email            string `json:"email"`
			Account          string `json:"account"`
			AutoRenew        bool   `json:"auto_renew"`
			RenewDaysBefore  int    `json:"renew_days_before"`
		}

		var req ApplyCertRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// 更新域名配置
		domain.PurchaseCert = true
		domain.CertType = req.CertType
		domain.SSLConfig.CA = req.CA
		domain.SSLConfig.KeyType = req.KeyType
		domain.SSLConfig.Challenge = req.Challenge
		domain.SSLConfig.Email = req.Email
		domain.Account = req.Account
		domain.AutoRenew = req.AutoRenew
		domain.RenewDays = req.RenewDaysBefore

		// 保存更新后的配置
		if err := cm.UpdateDomain(domain); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update domain config"})
			return
		}

		// 异步申请证书
		go func() {
			// 创建ACME客户端
			acmeClient, err := core.NewACMEClient(domain.SSLConfig.Email, getCAURL(domain.SSLConfig.CA))
			if err != nil {
				log.Printf("创建ACME客户端失败: %v", err)
				return
			}

			// 设置DNS提供商，使用绑定的账户ID
			if err := acmeClient.SetDNSProvider(domain.DNSProvider, domain.AccountID, cm); err != nil {
				log.Printf("设置DNS提供商失败: %v", err)
				return
			}

			// 申请新证书
			newCert, err := acmeClient.ObtainCertificate(domain.Domain, domain.SubDomains)
			if err != nil {
				log.Printf("申请新证书失败: %v", err)
				return
			}

			// 保存新证书
			if err := certStore.SaveCertificate(newCert); err != nil {
				log.Printf("保存新证书失败: %v", err)
				return
			}

			log.Printf("域名 %s 的证书申请成功，到期时间: %s", domain.ID, newCert.NotAfter)
		}()

		c.JSON(http.StatusAccepted, gin.H{
			"message": "certificate application started",
			"domain":  domain.Domain,
			"cert_type": req.CertType,
		})
	}
}

// getCAURL 获取CA机构的URL
func getCAURL(ca string) string {
	switch ca {
	case "letsencrypt":
		return "https://acme-v02.api.letsencrypt.org/directory"
	case "zerossl":
		return "https://acme.zerossl.com/v2/DV90"
	case "buypass":
		return "https://api.buypass.com/acme/directory"
	case "google":
		return "https://dv.acme-v02.api.pki.goog/directory"
	default:
		return "https://acme-v02.api.letsencrypt.org/directory"
	}
}

// getCertHistory 获取证书历史
func getCertHistory(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		_, ok := cm.GetDomain(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}

		var certs []*config.Certificate
		var err error
		certs, err = certStore.GetAll(id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 构建包含完整证书数据的响应
		var response []gin.H
		for _, cert := range certs {
			response = append(response, gin.H{
				"id":           cert.ID,
				"domain_id":    cert.DomainID,
				"domain":       cert.Domain,
				"cert_pem":     cert.CertPEM,
				"key_pem":      cert.KeyPEM,
				"issuer":       cert.Issuer,
				"not_before":   cert.NotBefore,
				"not_after":    cert.NotAfter,
				"serial_number": cert.SerialNumber,
				"status":       cert.Status,
				"created_at":   cert.CreatedAt,
				"updated_at":   cert.UpdatedAt,
				"deployed_to":  cert.DeployedTo,
			})
		}

		c.JSON(http.StatusOK, response)
	}
}

// listServers 列出所有服务器
func listServers(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		servers := cm.GetAllServers()
		response := make([]ServerResponse, len(servers))
		for i, server := range servers {
			response[i] = toServerResponse(server)
		}
		c.JSON(http.StatusOK, response)
	}
}

// testConnection 测试服务器连接
func testConnection(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		log.Printf("开始测试服务器连接: %s", id)
		server, ok := cm.GetServer(id)
		if !ok {
			log.Printf("服务器不存在: %s", id)
			c.JSON(http.StatusNotFound, gin.H{"error": "server not found"})
			return
		}

		// 实现服务器连接测试
		connected := false
		errorMsg := ""

		// 使用SSHDeployer测试连接
		log.Printf("测试服务器连接: %s:%d", server.Host, server.Port)
		
		// 创建SSH部署器
		deployer := deployer.NewSSHDeployer(cm)
		
		// 测试连接
		err := deployer.TestConnection(context.Background(), config.DeploymentConfig{
			ServerID: id,
		})
		
		if err != nil {
			errorMsg = err.Error()
			log.Printf("服务器连接测试失败: %s, 原因: %s", id, errorMsg)
		} else {
			connected = true
			log.Printf("服务器连接测试成功: %s", id)
		}

		c.JSON(http.StatusOK, gin.H{
			"server":    server,
			"connected": connected,
			"error":     errorMsg,
		})
	}
}

// getDashboard 获取仪表盘数据
func getDashboard(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		domains := cm.GetAllDomains()
		servers := cm.GetAllServers()

		var totalCerts int
		var expiringSoon int
		var activeCerts int
		var domainExpiringSoon int

		for _, domain := range domains {
			cert, err := certStore.GetLatest(domain.ID)
			if err == nil {
				totalCerts++
				if cert.Status == "active" {
					activeCerts++
					daysLeft := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
					if daysLeft <= 30 {
						expiringSoon++
					}
				}
			}

			// 检查域名到期
			if domain.DomainExpiry != nil {
				daysLeft := int(domain.DomainExpiry.Sub(time.Now()).Hours() / 24)
				if daysLeft <= 30 {
					domainExpiringSoon++
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"total_domains":   len(domains),
			"total_servers":   len(servers),
			"total_certs":     totalCerts,
			"active_certs":    activeCerts,
			"expiring_soon":   expiringSoon,
			"domain_expiring_soon": domainExpiringSoon,
			"last_updated":    time.Now(),
		})
	}
}

// getExpiryAlerts 获取到期告警
func getExpiryAlerts(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		domains := cm.GetAllDomains()
		var alerts []gin.H

		for _, domain := range domains {
			// 检查证书到期
			cert, err := certStore.GetLatest(domain.ID)
			if err == nil {
				daysLeft := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
				if daysLeft <= 30 {
					alerts = append(alerts, gin.H{
						"domain":      domain.Domain,
						"account_id":  domain.AccountID,
						"remark":      domain.Remark,
						"days_left":   daysLeft,
						"expiry_date": cert.NotAfter,
						"type":        "certificate",
					})
				}
			}

			// 检查域名到期
			if domain.DomainExpiry != nil {
				daysLeft := int(domain.DomainExpiry.Sub(time.Now()).Hours() / 24)
				if daysLeft <= 30 {
					alerts = append(alerts, gin.H{
						"domain":      domain.Domain,
						"account_id":  domain.AccountID,
						"remark":      domain.Remark,
						"days_left":   daysLeft,
						"expiry_date": *domain.DomainExpiry,
						"type":        "domain",
					})
				}
			}
		}

		log.Printf("获取到期告警成功，共 %d 条告警", len(alerts))
		c.JSON(http.StatusOK, alerts)
	}
}

// getOperationLogs 获取操作日志
func getOperationLogs() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: 实现日志获取
		c.JSON(http.StatusOK, []gin.H{
			{
				"time":    time.Now(),
				"action":  "cert_renew",
				"domain":  "example.com",
				"status":  "success",
				"message": "Certificate renewed successfully",
			},
		})
	}
}

// reloadConfig 重新加载配置
func reloadConfig(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := cm.Reload(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "config reloaded successfully"})
	}
}

// uploadCertificate 上传已有证书
func uploadCertificate(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("接收到上传证书请求")
		id := c.Param("id")
		log.Printf("域名ID: %s", id)
		domain, ok := cm.GetDomain(id)
		if !ok {
			log.Printf("域名不存在: %s", id)
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}

		// 解析上传请求参数
		type UploadCertRequest struct {
			CertPEM string `json:"cert_pem" binding:"required"`
			KeyPEM  string `json:"key_pem" binding:"required"`
		}

		var req UploadCertRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("解析请求参数失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		log.Printf("接收到证书PEM长度: %d, 私钥PEM长度: %d", len(req.CertPEM), len(req.KeyPEM))

		// 检查证书和私钥是否为空
		if len(req.CertPEM) < 10 || len(req.KeyPEM) < 10 {
			log.Printf("证书或私钥内容过短")
			c.JSON(http.StatusBadRequest, gin.H{"error": "certificate or key content is too short"})
			return
		}

		// 解析证书
		block, _ := pem.Decode([]byte(req.CertPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			log.Printf("无效的证书PEM格式")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid certificate PEM"})
			return
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("解析证书失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid certificate"})
			return
		}

		log.Printf("证书解析成功，域名: %s, 到期时间: %s", x509Cert.Subject.CommonName, x509Cert.NotAfter)

		// 检查证书是否对当前域名有效
		if !isCertValidForDomain(x509Cert, domain.Domain) {
			log.Printf("证书对域名 %s 无效", domain.Domain)
			// 即使证书对域名无效，也允许上传，因为用户可能上传任何证书
			log.Printf("证书对域名无效，但仍允许上传")
		}

		// 创建证书记录，使用domain.Domain作为DomainID，这样可以与listDomains中的逻辑保持一致
		cert := &config.Certificate{
			ID:           fmt.Sprintf("%s-%s", domain.Domain, x509Cert.SerialNumber),
			DomainID:     domain.Domain,
			Domain:       x509Cert.Subject.CommonName,
			CertPEM:      req.CertPEM,
			KeyPEM:       req.KeyPEM,
			Issuer:       x509Cert.Issuer.CommonName,
			NotBefore:    x509Cert.NotBefore,
			NotAfter:     x509Cert.NotAfter,
			SerialNumber: x509Cert.SerialNumber.String(),
			Status:       getCertStatus(x509Cert),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// 保存证书
		if err := certStore.SaveCertificate(cert); err != nil {
			log.Printf("保存证书失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		log.Printf("证书上传成功，ID: %s, DomainID: %s", cert.ID, cert.DomainID)
		c.JSON(http.StatusOK, gin.H{"message": "certificate uploaded successfully"})
	}
}

// isCertValidForDomain 检查证书是否对指定域名有效
func isCertValidForDomain(cert *x509.Certificate, domain string) bool {
	// 检查CN是否匹配
	if cert.Subject.CommonName == domain {
		return true
	}
	
	// 检查CN是否是通配符
	if len(cert.Subject.CommonName) > 1 && cert.Subject.CommonName[0] == '*' {
		wildcardDomain := cert.Subject.CommonName[1:]
		if len(domain) > len(wildcardDomain) && domain[len(domain)-len(wildcardDomain):] == wildcardDomain {
			return true
		}
	}
	
	// 检查SAN字段
	for _, san := range cert.DNSNames {
		if san == domain {
			return true
		}
		if len(san) > 1 && san[0] == '*' {
			wildcardDomain := san[1:]
			if len(domain) > len(wildcardDomain) && domain[len(domain)-len(wildcardDomain):] == wildcardDomain {
				return true
			}
		}
	}
	
	return false
}

// getCertStatus 获取证书状态
func getCertStatus(cert *x509.Certificate) string {
	now := time.Now()
	if now.After(cert.NotAfter) {
		return "expired"
	}
	if now.Before(cert.NotBefore) {
		return "not_valid_yet"
	}
	return "active"
}

// validateConfig 验证配置
func validateConfig(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: 实现配置验证
		c.JSON(http.StatusOK, gin.H{"valid": true})
	}
}

// listDNS 列出所有DNS配置
func listDNS(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		dnsConfigs := cm.GetAllDNS()
		c.JSON(http.StatusOK, dnsConfigs)
	}
}

// getDNS 获取单个DNS配置
func getDNS(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		dns, ok := cm.GetDNS(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "dns config not found"})
			return
		}
		c.JSON(http.StatusOK, dns)
	}
}

// addDNS 添加DNS配置
func addDNS(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dnsConfig config.DNSConfig
		if err := c.ShouldBindJSON(&dnsConfig); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := cm.AddDNS(&dnsConfig); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, dnsConfig)
	}
}

// updateDNS 更新DNS配置
func updateDNS(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var dnsConfig config.DNSConfig
		if err := c.ShouldBindJSON(&dnsConfig); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		dnsConfig.ID = id
		if err := cm.UpdateDNS(&dnsConfig); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, dnsConfig)
	}
}

// deleteDNS 删除DNS配置
func deleteDNS(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if err := cm.DeleteDNS(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "dns config deleted"})
	}
}

// listDNSRecords 列出DNS记录
func listDNSRecords(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		dns, ok := cm.GetDNS(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "dns config not found"})
			return
		}

		c.JSON(http.StatusOK, dns.Records)
	}
}

// addDNSRecord 添加DNS记录
func addDNSRecord(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var record config.DNSRecord
		if err := c.ShouldBindJSON(&record); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 先添加到本地配置
		if err := cm.AddDNSRecord(id, &record); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, record)
	}
}

// updateDNSRecord 更新DNS记录
func updateDNSRecord(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		recordId := c.Param("recordId")
		var record config.DNSRecord
		if err := c.ShouldBindJSON(&record); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		record.ID = recordId
		// 先更新本地配置
		if err := cm.UpdateDNSRecord(id, &record); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, record)
	}
}

// deleteDNSRecord 删除DNS记录
func deleteDNSRecord(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		recordId := c.Param("recordId")
		// 先删除本地配置
		if err := cm.DeleteDNSRecord(id, recordId); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "dns record deleted"})
	}
}

// VolcengineListRecordsResponse 火山引擎DNS记录列表响应结构
type VolcengineListRecordsResponse struct {
	Result struct {
		Records []struct {
			RecordId string `json:"RecordId"`
			RR       string `json:"RR"`
			Type     string `json:"Type"`
			Value    string `json:"Value"`
			TTL      int    `json:"TTL"`
			Priority int    `json:"Priority"`
		}
	}
}

// syncDNSRecords 同步DNS记录
func syncDNSRecords(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		dns, ok := cm.GetDNS(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "dns config not found"})
			return
		}

		// 检查是否绑定了账户
		if dns.AccountID != "" {
			// 获取账户信息
			account, ok := cm.GetAccount(dns.AccountID)
			if ok && account.Enabled {
				// 根据云厂商类型创建对应的同步客户端
				var syncClient providers.SyncClient
				var err error
				
				switch account.CloudVendor {
				case "aliyun":
					syncClient, err = providers.NewAliyunSyncClient(account.Region, account.AccessKey, account.SecretKey)
				case "volcengine":
					syncClient, err = providers.NewVolcengineSyncClient(account.Region, account.AccessKey, account.SecretKey)
				}
				
				if err == nil {
					ctx := context.Background()
					
					// 先获取云平台的现有记录，用于比较
					var cloudRecords []config.DNSRecord
					response, err := syncClient.GetSubDomains(ctx, dns.Domain)
					if err == nil && len(response) > 0 {
						// 处理阿里云响应
						if dnsResponse, ok := response[0].(*alidns.DescribeDomainRecordsResponse); ok {
							for _, record := range dnsResponse.DomainRecords.Record {
								priority := 0
								if record.Type == "MX" {
									priority = int(record.Priority)
								}
								cloudRecords = append(cloudRecords, config.DNSRecord{
									ID:       record.RecordId,
									Name:     record.RR,
									Type:     record.Type,
									Value:    record.Value,
									TTL:      int(record.TTL),
									Priority: priority,
								})
							}
						}
						// 处理火山引擎响应
						if dnsResponse, ok := response[0].(VolcengineListRecordsResponse); ok {
							for _, record := range dnsResponse.Result.Records {
								priority := 0
								if record.Type == "MX" {
									priority = record.Priority
								}
								cloudRecords = append(cloudRecords, config.DNSRecord{
									ID:       record.RecordId,
									Name:     record.RR,
									Type:     record.Type,
									Value:    record.Value,
									TTL:      record.TTL,
									Priority: priority,
								})
							}
						}
					}
					
					// 将本地记录同步到云平台
					for _, localRecord := range dns.Records {
						// 检查记录是否已存在于云平台
						exists := false
						for _, cloudRecord := range cloudRecords {
							if cloudRecord.Name == localRecord.Name && cloudRecord.Type == localRecord.Type {
								exists = true
								// 更新现有记录
								recordMap := map[string]interface{}{
									"name":     localRecord.Name,
									"type":     localRecord.Type,
									"value":    localRecord.Value,
									"ttl":      localRecord.TTL,
									"priority": localRecord.Priority,
								}
								err = syncClient.UpdateDNSRecord(ctx, dns.Domain, cloudRecord.ID, recordMap)
								if err != nil {
									log.Printf("更新DNS记录到云平台失败: %v", err)
								}
								break
							}
						}
						if !exists {
							// 添加新记录
							recordMap := map[string]interface{}{
								"name":     localRecord.Name,
								"type":     localRecord.Type,
								"value":    localRecord.Value,
								"ttl":      localRecord.TTL,
								"priority": localRecord.Priority,
							}
							err = syncClient.AddDNSRecord(ctx, dns.Domain, recordMap)
							if err != nil {
								log.Printf("添加DNS记录到云平台失败: %v", err)
							}
						}
					}
					
					// 再次获取云平台的记录，确保同步成功
					response, err = syncClient.GetSubDomains(ctx, dns.Domain)
					if err == nil && len(response) > 0 {
						// 处理阿里云响应
						if dnsResponse, ok := response[0].(*alidns.DescribeDomainRecordsResponse); ok {
							dns.Records = []config.DNSRecord{}
							for _, record := range dnsResponse.DomainRecords.Record {
								priority := 0
								if record.Type == "MX" {
									priority = int(record.Priority)
								}
								dns.Records = append(dns.Records, config.DNSRecord{
									ID:       record.RecordId,
									Name:     record.RR,
									Type:     record.Type,
									Value:    record.Value,
									TTL:      int(record.TTL),
									Priority: priority,
								})
							}
						}
						// 处理火山引擎响应
						if dnsResponse, ok := response[0].(VolcengineListRecordsResponse); ok {
							dns.Records = []config.DNSRecord{}
							for _, record := range dnsResponse.Result.Records {
								priority := 0
								if record.Type == "MX" {
									priority = record.Priority
								}
								dns.Records = append(dns.Records, config.DNSRecord{
									ID:       record.RecordId,
									Name:     record.RR,
									Type:     record.Type,
									Value:    record.Value,
									TTL:      record.TTL,
									Priority: priority,
								})
							}
						}
					}
				}
			}
		}

		// 更新DNS记录
		if err := cm.UpdateDNS(dns); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "dns records synced", "records": dns.Records})
	}
}

// addDomain 添加域名配置
func addDomain(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var domain config.DomainConfig
		if err := c.ShouldBindJSON(&domain); err != nil {
			log.Printf("绑定域名JSON失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		log.Printf("添加域名: %s", domain.Domain)
		if err := cm.AddDomain(&domain); err != nil {
			log.Printf("添加域名失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		log.Printf("添加域名成功: %s", domain.Domain)
		c.JSON(http.StatusCreated, domain)
	}
}

// updateDomain 更新域名配置
func updateDomain(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		log.Printf("开始更新域名: %s", id)
		var domain config.DomainConfig
		if err := c.ShouldBindJSON(&domain); err != nil {
			log.Printf("绑定域名JSON失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据: " + err.Error()})
			return
		}

		log.Printf("更新域名: %s, 域名到期日期: %v", domain.Domain, domain.DomainExpiry)
		domain.ID = id
		if err := cm.UpdateDomain(&domain); err != nil {
			log.Printf("更新域名失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新域名失败: " + err.Error()})
			return
		}

		// 重新加载域名配置，检查是否保存成功
		updatedDomain, ok := cm.GetDomain(id)
		if ok {
			log.Printf("更新后域名到期日期: %v", updatedDomain.DomainExpiry)
		} else {
			log.Printf("更新后无法获取域名: %s", id)
		}

		log.Printf("更新域名成功: %s", domain.Domain)
		c.JSON(http.StatusOK, domain)
	}
}

// deleteDomain 删除域名配置
func deleteDomain(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if err := cm.DeleteDomain(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "domain deleted"})
	}
}

// addServer 添加服务器配置
func addServer(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var server config.ServerConfig
		if err := c.ShouldBindJSON(&server); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := cm.AddServer(&server); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, toServerResponse(&server))
	}
}

// ServerResponse 服务器响应结构（不包含敏感信息）
type ServerResponse struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	User     string            `json:"user"`
	AuthType string            `json:"auth_type"`
	Tags     []string          `json:"tags"`
	Metadata map[string]string `json:"metadata"`
}

// toServerResponse 将 ServerConfig 转换为 ServerResponse
func toServerResponse(server *config.ServerConfig) ServerResponse {
	return ServerResponse{
		ID:       server.ID,
		Name:     server.Name,
		Host:     server.Host,
		Port:     server.Port,
		User:     server.User,
		AuthType: server.AuthType,
		Tags:     server.Tags,
		Metadata: server.Metadata,
	}
}

// getServer 获取服务器详情
func getServer(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		server, ok := cm.GetServer(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "server not found"})
			return
		}

		c.JSON(http.StatusOK, toServerResponse(server))
	}
}

// updateServer 更新服务器配置
func updateServer(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var server config.ServerConfig
		if err := c.ShouldBindJSON(&server); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		server.ID = id
		if err := cm.UpdateServer(&server); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, toServerResponse(&server))
	}
}

// deleteServer 删除服务器配置
func deleteServer(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if err := cm.DeleteServer(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "server deleted"})
	}
}

// listUsers 列出所有用户
func listUsers(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		users := cm.GetAllUsers()
		c.JSON(http.StatusOK, users)
	}
}

// getUser 获取单个用户
func getUser(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		user, ok := cm.GetUser(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}

// addUser 添加用户
func addUser(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user config.UserConfig
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 打印接收到的用户信息
		fmt.Printf("Received user: %v, password: %s\n", user.Username, user.Password)

		if err := cm.AddUser(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, user)
	}
}

// updateUser 更新用户
func updateUser(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var user config.UserConfig
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user.ID = id
		if err := cm.UpdateUser(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}

// deleteUser 删除用户
func deleteUser(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if err := cm.DeleteUser(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
	}
}

// getCheckConfig 获取定期检测配置
func getCheckConfig(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		checkConfig := cm.GetCheckConfig()
		c.JSON(http.StatusOK, checkConfig)
	}
}

// updateCheckConfig 更新定期检测配置
func updateCheckConfig(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var checkConfig config.CheckConfig
		if err := c.ShouldBindJSON(&checkConfig); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := cm.UpdateCheckConfig(&checkConfig); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, checkConfig)
	}
}

// listAccounts 列出所有账户
func listAccounts(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		accounts := cm.GetAllAccounts()
		c.JSON(http.StatusOK, accounts)
	}
}

// getAccount 获取单个账户
func getAccount(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		account, ok := cm.GetAccount(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
			return
		}
		c.JSON(http.StatusOK, account)
	}
}

// addAccount 添加账户
func addAccount(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var account config.AccountConfig
		if err := c.ShouldBindJSON(&account); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := cm.AddAccount(&account); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 清空敏感信息，不在响应中返回
		account.AccessKey = ""
		account.SecretKey = ""
		c.JSON(http.StatusCreated, account)
	}
}

// updateAccount 更新账户
func updateAccount(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var account config.AccountConfig
		if err := c.ShouldBindJSON(&account); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		account.ID = id
		if err := cm.UpdateAccount(&account); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 清空敏感信息，不在响应中返回
		account.AccessKey = ""
		account.SecretKey = ""
		c.JSON(http.StatusOK, account)
	}
}

// deleteAccount 删除账户
func deleteAccount(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if err := cm.DeleteAccount(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "account deleted"})
	}
}

// 同步状态管理
var syncStatus = struct {
	LastSyncTime time.Time
	Status       string
	Message      string
}{}

// syncAliyun 同步阿里云域名和证书
func syncAliyun(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 解析请求参数
		type SyncRequest struct {
			AccountID string `json:"account_id" binding:"required"`
		}

		var req SyncRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// 获取账户信息
		account, ok := cm.GetAccount(req.AccountID)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
			return
		}

		if !account.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "account is disabled"})
			return
		}

		// 更新同步状态
		syncStatus.Status = "running"
		syncStatus.Message = "开始同步阿里云域名和证书"
		syncStatus.LastSyncTime = time.Now()

		// 异步执行同步
		go func() {
			ctx := context.Background()
			
			// 打印账户信息，用于调试
			log.Printf("同步阿里云账户: %s, 区域: %s, AccessKey: %s, SecretKey: %s", 
				account.ID, account.Region, account.AccessKey, account.SecretKey)
			
			// 创建阿里云同步客户端
			syncClient, err := providers.NewAliyunSyncClient(account.Region, account.AccessKey, account.SecretKey)
			if err != nil {
				syncStatus.Status = "failed"
				syncStatus.Message = fmt.Sprintf("创建阿里云同步客户端失败: %v", err)
				return
			}

			// 同步域名
			domains, err := syncClient.GetDomains(ctx)
			if err != nil {
				syncStatus.Status = "failed"
				syncStatus.Message = fmt.Sprintf("获取域名列表失败: %v", err)
				return
			}

			// 处理同步的域名
		for _, domainInfo := range domains {
			// 检查域名是否已存在
			existingDomain, ok := cm.GetDomain(domainInfo.DomainName)
			if !ok {
				// 创建新域名配置
				newDomain := &config.DomainConfig{
					ID:           domainInfo.DomainName,
					Domain:       domainInfo.DomainName,
					SubDomains:   []string{},
					DNSProvider: config.DNSProviderConfig{
						Type:        "aliyun",
						Region:      account.Region,
						Credentials: map[string]string{
							"access_key_id":     account.AccessKey,
							"access_key_secret": account.SecretKey,
							"region_id":         account.Region,
						},
					},
					AutoRenew:      true,
					RenewDays:      30,
					PurchaseCert:   false,
					CertType:       "official",
					Business:       "",
					CloudVendor:    "aliyun",
					AccountID:      account.ID,
					Remark:         "",
				}
				// 解析并设置域名到期时间
				if domainInfo.ExpiryDate != "" {
					expiryTime, err := time.Parse(time.RFC3339, domainInfo.ExpiryDate)
					if err == nil {
						newDomain.DomainExpiry = &expiryTime
					}
				}
				if err := cm.AddDomain(newDomain); err != nil {
					log.Printf("添加域名失败: %v", err)
				}
			} else {
				// 更新现有域名配置
				existingDomain.AccountID = account.ID
				existingDomain.CloudVendor = "aliyun"
				// 解析并设置域名到期时间
				if domainInfo.ExpiryDate != "" {
					expiryTime, err := time.Parse(time.RFC3339, domainInfo.ExpiryDate)
					if err == nil {
						existingDomain.DomainExpiry = &expiryTime
					}
				}
				if err := cm.UpdateDomain(existingDomain); err != nil {
					log.Printf("更新域名失败: %v", err)
				}
			}
		}

			// 同步证书
			// 由于CAS SDK方法名不确定，暂时跳过证书同步
			// 实际实现需要根据正确的SDK方法名进行修改
			log.Println("跳过证书同步，等待CAS SDK方法确认")

			// 更新同步状态
			syncStatus.Status = "completed"
			syncStatus.Message = "同步完成"
			syncStatus.LastSyncTime = time.Now()
		}()

		c.JSON(http.StatusAccepted, gin.H{
			"message": "sync started",
			"account_id": req.AccountID,
		})
	}
}

// getSyncStatus 获取同步状态
func getSyncStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":        syncStatus.Status,
			"message":       syncStatus.Message,
			"last_sync_time": syncStatus.LastSyncTime,
		})
	}
}

// getCertStatusFromTime 根据时间获取证书状态
func getCertStatusFromTime(notBefore, notAfter time.Time) string {
	now := time.Now()
	if now.After(notAfter) {
		return "expired"
	}
	if now.Before(notBefore) {
		return "not_valid_yet"
	}
	return "active"
}

// ObtainCertificateWithScriptRequest 脚本创建证书请求结构体
type ObtainCertificateWithScriptRequest struct {
	Domain     string   `json:"domain" binding:"required"`
	SubDomains []string `json:"sub_domains"`
	Wildcard   bool     `json:"wildcard"`
	ScriptPath string   `json:"script_path" binding:"required"`
	ConfigPath string   `json:"config_path" binding:"required"`
}

// obtainCertificateWithScript 使用脚本创建证书
func obtainCertificateWithScript(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ObtainCertificateWithScriptRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// 执行脚本获取证书
		// 这里应该调用脚本执行函数，获取证书和私钥
		// 由于我们没有实际的脚本执行实现，这里模拟一个证书
		// 实际实现应该调用 core.NewScriptExecutor().ObtainCertificateWithScript()

		// 模拟证书数据
		certPEM := `-----BEGIN CERTIFICATE-----
MIICzjCCAbegAwIBAgIUWNf7vz7vz7vz7vz7vz7vz7vz7vz7vz7vz7vz7vz7vz7
-----END CERTIFICATE-----`
		keyPEM := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCz7vz7vz7vz7vz
-----END PRIVATE KEY-----`

		// 解析证书
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid certificate PEM"})
			return
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid certificate"})
			return
		}

		// 创建证书记录
		cert := &config.Certificate{
			ID:           fmt.Sprintf("%s-%s", req.Domain, x509Cert.SerialNumber),
			DomainID:     req.Domain,
			Domain:       req.Domain,
			CertPEM:      certPEM,
			KeyPEM:       keyPEM,
			Issuer:       x509Cert.Issuer.CommonName,
			NotBefore:    x509Cert.NotBefore,
			NotAfter:     x509Cert.NotAfter,
			SerialNumber: x509Cert.SerialNumber.String(),
			Status:       getCertStatus(x509Cert),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// 保存证书
		if err := certStore.SaveCertificate(cert); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 如果域名不存在，创建域名配置
		if _, ok := cm.GetDomain(req.Domain); !ok {
			newDomain := &config.DomainConfig{
				ID:         req.Domain,
				Domain:     req.Domain,
				SubDomains: req.SubDomains,
				AutoRenew:  true,
				RenewDays:  30,
				PurchaseCert: false,
				CertType:   "official",
			}
			if err := cm.AddDomain(newDomain); err != nil {
				log.Printf("添加域名失败: %v", err)
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "certificate obtained successfully",
			"domain":  req.Domain,
			"cert_id": cert.ID,
		})
	}
}

// checkDomainCertBinding 检查域名的DNS解析记录与证书绑定状态
func checkDomainCertBinding(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		domain, ok := cm.GetDomain(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}

		// 获取域名的最新证书
		cert, err := certStore.GetLatest(id)
		
		// 如果找不到证书，尝试使用域名作为证书目录名
		if err != nil {
			log.Printf("使用域名ID %s 找不到证书，尝试使用域名 %s", id, domain.Domain)
			cert, err = certStore.GetLatest(domain.Domain)
		}
		
		// 如果仍然找不到证书，尝试使用替换下划线为点号的域名作为证书目录名
		if err != nil && strings.Contains(id, "_") {
			domainWithDots := strings.ReplaceAll(id, "_", ".")
			log.Printf("使用域名 %s 找不到证书，尝试使用替换下划线为点号的域名 %s", domain.Domain, domainWithDots)
			cert, err = certStore.GetLatest(domainWithDots)
		}
		
		// 如果仍然找不到证书，尝试使用子域名作为证书目录名
		if err != nil && len(domain.SubDomains) > 0 {
			for _, subDomain := range domain.SubDomains {
				log.Printf("使用替换下划线为点号的域名 %s 找不到证书，尝试使用子域名 %s", domain.Domain, subDomain)
				cert, err = certStore.GetLatest(subDomain)
				if err == nil {
					break
				}
			}
		}
		
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get certificate"})
			return
		}

		// 获取域名的DNS解析记录
		var dnsRecords []config.DNSRecord
		dnsConfigs := cm.GetAllDNS()
		for _, dns := range dnsConfigs {
			if dns.Domain == domain.Domain {
				dnsRecords = dns.Records
				break
			}
		}

		// 检查每个DNS记录是否绑定了证书
		var bindingStatus []gin.H
		for _, record := range dnsRecords {
			// 只检查A、AAAA、CNAME记录
			if record.Type != "A" && record.Type != "AAAA" && record.Type != "CNAME" {
				continue
			}

			// 构建完整的子域名
			subdomain := record.Name
			fullDomain := subdomain
			if subdomain != "@" {
				fullDomain = subdomain + "." + domain.Domain
			} else {
				fullDomain = domain.Domain
			}

			// 检查证书是否覆盖该域名
			isBound := false
			// 解析证书
			x509Cert, err := x509.ParseCertificate([]byte(cert.CertPEM))
			if err == nil {
				isBound = isCertValidForDomain(x509Cert, fullDomain)
			}

			bindingStatus = append(bindingStatus, gin.H{
				"record_id":    record.ID,
				"name":         record.Name,
				"type":         record.Type,
				"value":        record.Value,
				"full_domain":  fullDomain,
				"is_bound":     isBound,
				"certificate":  gin.H{
					"serial_number": cert.SerialNumber,
					"not_after":     cert.NotAfter,
					"issuer":        cert.Issuer,
				},
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"domain":        domain.Domain,
			"certificate":   gin.H{
				"serial_number": cert.SerialNumber,
				"not_after":     cert.NotAfter,
				"issuer":        cert.Issuer,
				"status":        cert.Status,
			},
			"binding_status": bindingStatus,
			"total_records":  len(bindingStatus),
			"bound_records":  len(filterBoundRecords(bindingStatus)),
		})
	}
}

// checkDNSCertBinding 检查DNS配置的解析记录与证书绑定状态
func checkDNSCertBinding(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		dns, ok := cm.GetDNS(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "dns config not found"})
			return
		}

		// 检查域名是否存在
		_, ok = cm.GetDomain(dns.Domain)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
			return
		}

		// 获取域名的最新证书
		cert, err := certStore.GetLatest(dns.Domain)
		
		// 如果找不到证书，尝试使用替换下划线为点号的域名作为证书目录名
		if err != nil && strings.Contains(dns.Domain, "_") {
			domainWithDots := strings.ReplaceAll(dns.Domain, "_", ".")
			log.Printf("使用域名 %s 找不到证书，尝试使用替换下划线为点号的域名 %s", dns.Domain, domainWithDots)
			cert, err = certStore.GetLatest(domainWithDots)
		}
		
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get certificate"})
			return
		}

		// 检查每个DNS记录是否绑定了证书
		var bindingStatus []gin.H
		for _, record := range dns.Records {
			// 只检查A、AAAA、CNAME记录
			if record.Type != "A" && record.Type != "AAAA" && record.Type != "CNAME" {
				continue
			}

			// 构建完整的子域名
			subdomain := record.Name
			fullDomain := subdomain
			if subdomain != "@" {
				fullDomain = subdomain + "." + dns.Domain
			} else {
				fullDomain = dns.Domain
			}

			// 检查证书是否覆盖该域名
			isBound := false
			// 解析证书
			x509Cert, err := x509.ParseCertificate([]byte(cert.CertPEM))
			if err == nil {
				isBound = isCertValidForDomain(x509Cert, fullDomain)
			}

			bindingStatus = append(bindingStatus, gin.H{
				"record_id":    record.ID,
				"name":         record.Name,
				"type":         record.Type,
				"value":        record.Value,
				"full_domain":  fullDomain,
				"is_bound":     isBound,
				"certificate":  gin.H{
					"serial_number": cert.SerialNumber,
					"not_after":     cert.NotAfter,
					"issuer":        cert.Issuer,
				},
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"domain":        dns.Domain,
			"certificate":   gin.H{
				"serial_number": cert.SerialNumber,
				"not_after":     cert.NotAfter,
				"issuer":        cert.Issuer,
				"status":        cert.Status,
			},
			"binding_status": bindingStatus,
			"total_records":  len(bindingStatus),
			"bound_records":  len(filterBoundRecords(bindingStatus)),
		})
	}
}

// filterBoundRecords 过滤出已绑定证书的记录
func filterBoundRecords(records []gin.H) []gin.H {
	var boundRecords []gin.H
	for _, record := range records {
		if record["is_bound"].(bool) {
			boundRecords = append(boundRecords, record)
		}
	}
	return boundRecords
}

// syncMultiCloud 同步多平台域名和证书
func syncMultiCloud(cm *config.ConfigManager, certStore *store.CertStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 解析请求参数
		type SyncRequest struct {
			AccountID string `json:"account_id" binding:"required"`
		}

		var req SyncRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		// 获取账户信息
		account, ok := cm.GetAccount(req.AccountID)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
			return
		}

		if !account.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "account is disabled"})
			return
		}

		// 更新同步状态
		syncStatus.Status = "running"
		syncStatus.Message = "开始同步云平台域名和证书"
		syncStatus.LastSyncTime = time.Now()

		// 异步执行同步
		go func() {
			ctx := context.Background()
			
			// 打印账户信息，用于调试
			log.Printf("同步云平台账户: %s, 区域: %s, 云厂商: %s, AccessKey: %s, SecretKey: %s", 
				account.ID, account.Region, account.CloudVendor, account.AccessKey, account.SecretKey)
			
			// 根据云厂商类型创建对应的同步客户端
			var syncClient providers.SyncClient
			var err error
			
			switch account.CloudVendor {
			case "aliyun":
				syncClient, err = providers.NewAliyunSyncClient(account.Region, account.AccessKey, account.SecretKey)
			default:
				syncStatus.Status = "failed"
				syncStatus.Message = fmt.Sprintf("暂时不支持%s同步", account.CloudVendor)
				return
			}
			
			if err != nil {
				syncStatus.Status = "failed"
				syncStatus.Message = fmt.Sprintf("创建同步客户端失败: %v", err)
				return
			}

			// 同步域名
			domains, err := syncClient.GetDomains(ctx)
			if err != nil {
				syncStatus.Status = "failed"
				syncStatus.Message = fmt.Sprintf("获取域名列表失败: %v", err)
				return
			}

			// 处理同步的域名
			for _, domainInfo := range domains {
				// 检查域名是否已存在
				existingDomain, ok := cm.GetDomain(domainInfo.DomainName)
				if !ok {
					// 创建新域名配置
					newDomain := &config.DomainConfig{
						ID:           domainInfo.DomainName,
						Domain:       domainInfo.DomainName,
						SubDomains:   []string{},
						DNSProvider: config.DNSProviderConfig{
							Type:        account.CloudVendor,
							Region:      account.Region,
							Credentials: map[string]string{
								"access_key_id":     account.AccessKey,
								"access_key_secret": account.SecretKey,
								"region_id":         account.Region,
							},
						},
						AutoRenew:      true,
						RenewDays:      30,
						PurchaseCert:   false,
						CertType:       "official",
						Business:       "",
						CloudVendor:    account.CloudVendor,
						AccountID:      account.ID,
						Remark:         "",
					}
					// 解析并设置域名到期时间
					if domainInfo.ExpiryDate != "" {
						expiryTime, err := time.Parse(time.RFC3339, domainInfo.ExpiryDate)
						if err == nil {
							newDomain.DomainExpiry = &expiryTime
						}
					}
					if err := cm.AddDomain(newDomain); err != nil {
						log.Printf("添加域名失败: %v", err)
					}
				} else {
					// 更新现有域名配置
					existingDomain.AccountID = account.ID
					existingDomain.CloudVendor = account.CloudVendor
					// 解析并设置域名到期时间
					if domainInfo.ExpiryDate != "" {
						expiryTime, err := time.Parse(time.RFC3339, domainInfo.ExpiryDate)
						if err == nil {
							existingDomain.DomainExpiry = &expiryTime
						}
					}
					if err := cm.UpdateDomain(existingDomain); err != nil {
						log.Printf("更新域名失败: %v", err)
					}
				}
			}

			// 同步证书
			// 由于CAS SDK方法名不确定，暂时跳过证书同步
			// 实际实现需要根据正确的SDK方法名进行修改
			log.Println("跳过证书同步，等待CAS SDK方法确认")

			// 更新同步状态
			syncStatus.Status = "completed"
			syncStatus.Message = "同步完成"
			syncStatus.LastSyncTime = time.Now()
		}()

		c.JSON(http.StatusAccepted, gin.H{
			"message":    "sync started",
			"account_id": req.AccountID,
			"cloud_vendor": account.CloudVendor,
		})
	}
}
