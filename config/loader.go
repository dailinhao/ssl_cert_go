package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// NewConfigManager 创建配置管理器
func NewConfigManager() *ConfigManager {
	cm := &ConfigManager{
		domains:     make(map[string]*DomainConfig),
		servers:     make(map[string]*ServerConfig),
		dnsConfigs:  make(map[string]*DNSConfig),
		users:       make(map[string]*UserConfig),
		accounts:    make(map[string]*AccountConfig),
	}

	// 尝试从数据库加载配置
	dbManager, err := GetDatabaseManager()
	if err != nil {
		fmt.Printf("Warning: Failed to initialize database manager: %v\n", err)
		fmt.Println("Falling back to file system storage")
	} else {
		cm.dbManager = dbManager
	}

	cm.LoadAll()
	return cm
}

// LoadAll 加载所有配置
func (cm *ConfigManager) LoadAll() error {
	if err := cm.loadDomains(); err != nil {
		return fmt.Errorf("load domains failed: %v", err)
	}
	if err := cm.loadServers(); err != nil {
		return fmt.Errorf("load servers failed: %v", err)
	}
	if err := cm.loadDNS(); err != nil {
		return fmt.Errorf("load dns failed: %v", err)
	}
	if err := cm.loadCheckConfig(); err != nil {
		return fmt.Errorf("load check config failed: %v", err)
	}
	if err := cm.loadUsers(); err != nil {
		return fmt.Errorf("load users failed: %v", err)
	}
	if err := cm.loadAccounts(); err != nil {
		return fmt.Errorf("load accounts failed: %v", err)
	}
	return nil
}

// loadDomains 加载域名配置
func (cm *ConfigManager) loadDomains() error {
	// 如果数据库管理器存在，从数据库加载
	if cm.dbManager != nil {
		domains, err := cm.dbManager.GetAllDomains()
		if err != nil {
			return err
		}

		// 清空当前域名映射
		cm.domains = make(map[string]*DomainConfig)

		// 将从数据库加载的域名添加到映射中
		for _, domain := range domains {
			cm.domains[domain.ID] = domain
		}

		return nil
	}

	// 否则，从文件系统加载
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	domainDir := filepath.Join(execDir, "configs", "domains")
	files, err := os.ReadDir(domainDir)
	if err != nil {
		if os.IsNotExist(err) {
			// 域名目录不存在，创建空目录
			if err := os.MkdirAll(domainDir, 0755); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(domainDir, file.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var domain DomainConfig
		if err := yaml.Unmarshal(content, &domain); err != nil {
			return fmt.Errorf("unmarshal domain config %s failed: %v", path, err)
		}

		if domain.ID == "" {
			domain.ID = domain.Domain
		}
		cm.domains[domain.ID] = &domain
	}

	return nil
}

// loadServers 加载服务器配置
func (cm *ConfigManager) loadServers() error {
	// 如果数据库管理器存在，从数据库加载
	if cm.dbManager != nil {
		servers, err := cm.dbManager.GetAllServers()
		if err != nil {
			return err
		}

		// 清空当前服务器映射
		cm.servers = make(map[string]*ServerConfig)

		// 将从数据库加载的服务器添加到映射中
		for _, server := range servers {
			cm.servers[server.ID] = server
		}

		return nil
	}

	// 否则，从文件系统加载
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	serverDir := filepath.Join(execDir, "configs", "servers")
	files, err := os.ReadDir(serverDir)
	if err != nil {
		if os.IsNotExist(err) {
			// 服务器目录不存在，创建空目录
			if err := os.MkdirAll(serverDir, 0755); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(serverDir, file.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var server ServerConfig
		if err := yaml.Unmarshal(content, &server); err != nil {
			return fmt.Errorf("unmarshal server config %s failed: %v", path, err)
		}

		cm.servers[server.ID] = &server
	}

	return nil
}

// GetAllDomains 获取所有域名配置
func (cm *ConfigManager) GetAllDomains() []*DomainConfig {
	var domains []*DomainConfig
	for _, domain := range cm.domains {
		domains = append(domains, domain)
	}
	return domains
}

// GetDomain 根据ID获取域名配置
func (cm *ConfigManager) GetDomain(id string) (*DomainConfig, bool) {
	domain, ok := cm.domains[id]
	return domain, ok
}

// GetAllServers 获取所有服务器配置
func (cm *ConfigManager) GetAllServers() []*ServerConfig {
	var servers []*ServerConfig
	for _, server := range cm.servers {
		servers = append(servers, server)
	}
	return servers
}

// GetServer 根据ID获取服务器配置
func (cm *ConfigManager) GetServer(id string) (*ServerConfig, bool) {
	server, ok := cm.servers[id]
	return server, ok
}

// AddDomain 添加域名配置
func (cm *ConfigManager) AddDomain(domain *DomainConfig) error {
	if domain.ID == "" {
		domain.ID = domain.Domain
	}

	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		if err := cm.dbManager.SaveDomain(domain); err != nil {
			return err
		}

		cm.domains[domain.ID] = domain
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	domainDir := filepath.Join(execDir, "configs", "domains")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return err
	}

	// 替换不允许的文件名字符
	safeID := strings.ReplaceAll(domain.ID, "*", "_")
	safeID = strings.ReplaceAll(safeID, "?", "_")
	safeID = strings.ReplaceAll(safeID, "<", "_")
	safeID = strings.ReplaceAll(safeID, ">", "_")
	safeID = strings.ReplaceAll(safeID, "|", "_")
	safeID = strings.ReplaceAll(safeID, "\"", "_")
	safeID = strings.ReplaceAll(safeID, "'", "_")
	safeID = strings.ReplaceAll(safeID, "`", "_")
	safeID = strings.ReplaceAll(safeID, "~", "_")
	safeID = strings.ReplaceAll(safeID, "!", "_")
	safeID = strings.ReplaceAll(safeID, "@", "_")
	safeID = strings.ReplaceAll(safeID, "#", "_")
	safeID = strings.ReplaceAll(safeID, "$", "_")
	safeID = strings.ReplaceAll(safeID, "%", "_")
	safeID = strings.ReplaceAll(safeID, "^", "_")
	safeID = strings.ReplaceAll(safeID, "&", "_")
	safeID = strings.ReplaceAll(safeID, "*", "_")
	safeID = strings.ReplaceAll(safeID, "(", "_")
	safeID = strings.ReplaceAll(safeID, ")", "_")
	safeID = strings.ReplaceAll(safeID, "+", "_")
	safeID = strings.ReplaceAll(safeID, "=", "_")
	safeID = strings.ReplaceAll(safeID, "[", "_")
	safeID = strings.ReplaceAll(safeID, "]", "_")
	safeID = strings.ReplaceAll(safeID, "{", "_")
	safeID = strings.ReplaceAll(safeID, "}", "_")
	safeID = strings.ReplaceAll(safeID, ";", "_")
	safeID = strings.ReplaceAll(safeID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "'", "_")
	safeID = strings.ReplaceAll(safeID, "\"", "_")
	safeID = strings.ReplaceAll(safeID, ",", "_")
	safeID = strings.ReplaceAll(safeID, ".", "_")
	safeID = strings.ReplaceAll(safeID, "<", "_")
	safeID = strings.ReplaceAll(safeID, ">", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	safeID = strings.ReplaceAll(safeID, "?", "_")
	safeID = strings.ReplaceAll(safeID, "|", "_")
	path := filepath.Join(domainDir, safeID+".yaml")
	content, err := yaml.Marshal(domain)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.domains[domain.ID] = domain
	return nil
}

// UpdateDomain 更新域名配置
func (cm *ConfigManager) UpdateDomain(domain *DomainConfig) error {
	// 检查域名是否存在
	if _, ok := cm.domains[domain.ID]; !ok {
		// 如果域名不存在，自动创建
		return cm.AddDomain(domain)
	}

	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		if err := cm.dbManager.SaveDomain(domain); err != nil {
			return err
		}

		cm.domains[domain.ID] = domain
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	domainDir := filepath.Join(execDir, "configs", "domains")
	// 替换不允许的文件名字符
	safeID := strings.ReplaceAll(domain.ID, "*", "_")
	safeID = strings.ReplaceAll(safeID, "?", "_")
	safeID = strings.ReplaceAll(safeID, "<", "_")
	safeID = strings.ReplaceAll(safeID, ">", "_")
	safeID = strings.ReplaceAll(safeID, "|", "_")
	safeID = strings.ReplaceAll(safeID, "\"", "_")
	safeID = strings.ReplaceAll(safeID, "'", "_")
	safeID = strings.ReplaceAll(safeID, "`", "_")
	safeID = strings.ReplaceAll(safeID, "~", "_")
	safeID = strings.ReplaceAll(safeID, "!", "_")
	safeID = strings.ReplaceAll(safeID, "@", "_")
	safeID = strings.ReplaceAll(safeID, "#", "_")
	safeID = strings.ReplaceAll(safeID, "$", "_")
	safeID = strings.ReplaceAll(safeID, "%", "_")
	safeID = strings.ReplaceAll(safeID, "^", "_")
	safeID = strings.ReplaceAll(safeID, "&", "_")
	safeID = strings.ReplaceAll(safeID, "*", "_")
	safeID = strings.ReplaceAll(safeID, "(", "_")
	safeID = strings.ReplaceAll(safeID, ")", "_")
	safeID = strings.ReplaceAll(safeID, "+", "_")
	safeID = strings.ReplaceAll(safeID, "=", "_")
	safeID = strings.ReplaceAll(safeID, "[", "_")
	safeID = strings.ReplaceAll(safeID, "]", "_")
	safeID = strings.ReplaceAll(safeID, "{", "_")
	safeID = strings.ReplaceAll(safeID, "}", "_")
	safeID = strings.ReplaceAll(safeID, ";", "_")
	safeID = strings.ReplaceAll(safeID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "'", "_")
	safeID = strings.ReplaceAll(safeID, "\"", "_")
	safeID = strings.ReplaceAll(safeID, ",", "_")
	safeID = strings.ReplaceAll(safeID, ".", "_")
	safeID = strings.ReplaceAll(safeID, "<", "_")
	safeID = strings.ReplaceAll(safeID, ">", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	safeID = strings.ReplaceAll(safeID, "?", "_")
	safeID = strings.ReplaceAll(safeID, "|", "_")
	path := filepath.Join(domainDir, safeID+".yaml")
	content, err := yaml.Marshal(domain)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.domains[domain.ID] = domain
	return nil
}

// DeleteDomain 删除域名配置
func (cm *ConfigManager) DeleteDomain(id string) error {
	if id == "" {
		return fmt.Errorf("domain ID cannot be empty")
	}

	if _, ok := cm.domains[id]; !ok {
		return fmt.Errorf("domain %s not found", id)
	}

	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		if err := cm.dbManager.DeleteDomain(id); err != nil {
			return err
		}

		delete(cm.domains, id)
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	domainDir := filepath.Join(execDir, "configs", "domains")

	// 打印调试信息
	log.Printf("DeleteDomain: id=%s", id)
	log.Printf("DeleteDomain: domainDir=%s", domainDir)

	// 尝试1：直接使用原始ID作为文件名（不替换点号）
	path1 := filepath.Join(domainDir, id+".yaml")
	log.Printf("DeleteDomain: trying path1=%s", path1)
	if err := os.Remove(path1); err == nil {
		log.Printf("DeleteDomain: deleted path1=%s", path1)
		delete(cm.domains, id)
		return nil
	} else {
		log.Printf("DeleteDomain: error removing path1=%s: %v", path1, err)
	}

	// 尝试2：按照AddDomain和UpdateDomain方法的逻辑构建文件名（替换点号为下划线）
	safeID := strings.ReplaceAll(id, "*", "_")
	safeID = strings.ReplaceAll(safeID, "?", "_")
	safeID = strings.ReplaceAll(safeID, "<", "_")
	safeID = strings.ReplaceAll(safeID, ">", "_")
	safeID = strings.ReplaceAll(safeID, "|", "_")
	safeID = strings.ReplaceAll(safeID, "\"", "_")
	safeID = strings.ReplaceAll(safeID, "'", "_")
	safeID = strings.ReplaceAll(safeID, "`", "_")
	safeID = strings.ReplaceAll(safeID, "~", "_")
	safeID = strings.ReplaceAll(safeID, "!", "_")
	safeID = strings.ReplaceAll(safeID, "@", "_")
	safeID = strings.ReplaceAll(safeID, "#", "_")
	safeID = strings.ReplaceAll(safeID, "$", "_")
	safeID = strings.ReplaceAll(safeID, "%", "_")
	safeID = strings.ReplaceAll(safeID, "^", "_")
	safeID = strings.ReplaceAll(safeID, "&", "_")
	safeID = strings.ReplaceAll(safeID, "*", "_")
	safeID = strings.ReplaceAll(safeID, "(", "_")
	safeID = strings.ReplaceAll(safeID, ")", "_")
	safeID = strings.ReplaceAll(safeID, "+", "_")
	safeID = strings.ReplaceAll(safeID, "=", "_")
	safeID = strings.ReplaceAll(safeID, "[", "_")
	safeID = strings.ReplaceAll(safeID, "]", "_")
	safeID = strings.ReplaceAll(safeID, "{", "_")
	safeID = strings.ReplaceAll(safeID, "}", "_")
	safeID = strings.ReplaceAll(safeID, ";", "_")
	safeID = strings.ReplaceAll(safeID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "'", "_")
	safeID = strings.ReplaceAll(safeID, "\"", "_")
	safeID = strings.ReplaceAll(safeID, ",", "_")
	safeID = strings.ReplaceAll(safeID, ".", "_")
	safeID = strings.ReplaceAll(safeID, "<", "_")
	safeID = strings.ReplaceAll(safeID, ">", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	safeID = strings.ReplaceAll(safeID, "?", "_")
	safeID = strings.ReplaceAll(safeID, "|", "_")

	path2 := filepath.Join(domainDir, safeID+".yaml")
	log.Printf("DeleteDomain: trying path2=%s", path2)
	if err := os.Remove(path2); err == nil {
		log.Printf("DeleteDomain: deleted path2=%s", path2)
		delete(cm.domains, id)
		return nil
	} else {
		log.Printf("DeleteDomain: error removing path2=%s: %v", path2, err)
	}

	// 尝试3：尝试其他可能的文件名格式
	// 3.1 尝试文件名前有空格的情况
	path3 := filepath.Join(domainDir, " "+id+".yaml")
	log.Printf("DeleteDomain: trying path3=%s", path3)
	if err := os.Remove(path3); err == nil {
		log.Printf("DeleteDomain: deleted path3=%s", path3)
		delete(cm.domains, id)
		return nil
	} else {
		log.Printf("DeleteDomain: error removing path3=%s: %v", path3, err)
	}

	// 3.2 尝试文件名前有双下划线的情况
	path4 := filepath.Join(domainDir, "__"+safeID+".yaml")
	log.Printf("DeleteDomain: trying path4=%s", path4)
	if err := os.Remove(path4); err == nil {
		log.Printf("DeleteDomain: deleted path4=%s", path4)
		delete(cm.domains, id)
		return nil
	} else {
		log.Printf("DeleteDomain: error removing path4=%s: %v", path4, err)
	}

	// 尝试列出目录中的所有文件，看看实际的文件名是什么
	files, err := os.ReadDir(domainDir)
	if err == nil {
		log.Printf("DeleteDomain: listing files in %s", domainDir)
		for _, file := range files {
			if !file.IsDir() {
				log.Printf("DeleteDomain: found file: %s", file.Name())
			}
		}
	}

	// 如果所有尝试都失败，返回错误
	return fmt.Errorf("failed to delete domain file: all possible file names not found")
}

// AddServer 添加服务器配置
func (cm *ConfigManager) AddServer(server *ServerConfig) error {
	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		if err := cm.dbManager.SaveServer(server); err != nil {
			return err
		}

		cm.servers[server.ID] = server
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	serverDir := filepath.Join(execDir, "configs", "servers")
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		return err
	}

	// 替换服务器ID中的点号为下划线，避免文件系统问题
	safeID := strings.ReplaceAll(server.ID, ".", "_")
	path := filepath.Join(serverDir, safeID+".yaml")
	content, err := yaml.Marshal(server)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.servers[server.ID] = server
	return nil
}

// UpdateServer 更新服务器配置
func (cm *ConfigManager) UpdateServer(server *ServerConfig) error {
	if _, ok := cm.servers[server.ID]; !ok {
		return fmt.Errorf("server %s not found", server.ID)
	}

	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		if err := cm.dbManager.SaveServer(server); err != nil {
			return err
		}

		cm.servers[server.ID] = server
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	serverDir := filepath.Join(execDir, "configs", "servers")
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		return err
	}

	// 替换服务器ID中的点号为下划线，避免文件系统问题
	safeID := strings.ReplaceAll(server.ID, ".", "_")
	path := filepath.Join(serverDir, safeID+".yaml")
	content, err := yaml.Marshal(server)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.servers[server.ID] = server
	return nil
}

// DeleteServer 删除服务器配置
func (cm *ConfigManager) DeleteServer(id string) error {
	if _, ok := cm.servers[id]; !ok {
		return fmt.Errorf("server %s not found", id)
	}

	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		if err := cm.dbManager.DeleteServer(id); err != nil {
			return err
		}

		delete(cm.servers, id)
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	serverDir := filepath.Join(execDir, "configs", "servers")

	// 替换服务器ID中的点号为下划线，避免文件系统问题
	safeID := strings.ReplaceAll(id, ".", "_")
	path := filepath.Join(serverDir, safeID+".yaml")
	if err := os.Remove(path); err != nil {
		return err
	}

	delete(cm.servers, id)
	return nil
}



// loadCheckConfig 加载定期检测配置
func (cm *ConfigManager) loadCheckConfig() error {
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	checkConfigFile := filepath.Join(execDir, "configs", "check.yaml")
	content, err := os.ReadFile(checkConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			// 配置文件不存在，使用默认配置
			cm.checkConfig = &CheckConfig{
				Enabled:  true,
				Interval: "24h",
				Checks: []CheckItem{
					{Type: "cert", Target: "all", Params: map[string]string{}},
					{Type: "server", Target: "all", Params: map[string]string{}},
				},
				Notifications: []NotificationConfig{},
			}
			return nil
		}
		return err
	}

	var checkConfig CheckConfig
	if err := yaml.Unmarshal(content, &checkConfig); err != nil {
		return err
	}

	cm.checkConfig = &checkConfig
	return nil
}

// GetCheckConfig 获取定期检测配置
func (cm *ConfigManager) GetCheckConfig() *CheckConfig {
	if cm.checkConfig == nil {
		// 返回默认配置
		return &CheckConfig{
			Enabled:  true,
			Interval: "24h",
			Checks: []CheckItem{
				{Type: "cert", Target: "all", Params: map[string]string{}},
				{Type: "server", Target: "all", Params: map[string]string{}},
			},
			Notifications: []NotificationConfig{},
		}
	}
	return cm.checkConfig
}

// UpdateCheckConfig 更新定期检测配置
func (cm *ConfigManager) UpdateCheckConfig(config *CheckConfig) error {
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	checkConfigFile := filepath.Join(execDir, "configs", "check.yaml")
	content, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	if err := os.WriteFile(checkConfigFile, content, 0644); err != nil {
		return err
	}

	cm.checkConfig = config
	return nil
}

// loadUsers 加载用户配置
func (cm *ConfigManager) loadUsers() error {
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	userDir := filepath.Join(execDir, "configs", "users")
	files, err := os.ReadDir(userDir)
	if err != nil {
		if os.IsNotExist(err) {
			// 用户目录不存在，创建默认管理员用户
			if err := os.MkdirAll(userDir, 0755); err != nil {
				return err
			}
			
			// 从.env文件中读取管理员密码
			adminPassword := os.Getenv("ADMIN_PASSWORD")
			if adminPassword == "" {
				adminPassword = "admin123" // 默认密码
			}
			
			// 创建默认管理员用户
			adminUser := &UserConfig{
				ID:        "admin",
				Username:  "admin",
				Password:  adminPassword, // 实际部署时应使用加密密码
				Email:     "admin@example.com",
				Role:      "admin",
				Enabled:   true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			
			content, err := yaml.Marshal(adminUser)
			if err != nil {
				return err
			}
			
			path := filepath.Join(userDir, adminUser.ID+".yaml")
			if err := os.WriteFile(path, content, 0644); err != nil {
				return err
			}
			
			cm.users[adminUser.ID] = adminUser
			return nil
		}
		return err
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(userDir, file.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var user UserConfig
		if err := yaml.Unmarshal(content, &user); err != nil {
			return fmt.Errorf("unmarshal user config %s failed: %v", path, err)
		}

		cm.users[user.ID] = &user
	}

	return nil
}

// GetAllUsers 获取所有用户
func (cm *ConfigManager) GetAllUsers() []*UserConfig {
	var users []*UserConfig
	for _, user := range cm.users {
		users = append(users, user)
	}
	return users
}

// GetUser 根据ID获取用户
func (cm *ConfigManager) GetUser(id string) (*UserConfig, bool) {
	user, ok := cm.users[id]
	return user, ok
}

// AddUser 添加用户
func (cm *ConfigManager) AddUser(user *UserConfig) error {
	if user.ID == "" {
		user.ID = user.Username
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	userDir := filepath.Join(execDir, "configs", "users")
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return err
	}

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	path := filepath.Join(userDir, user.ID+".yaml")
	content, err := yaml.Marshal(user)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.users[user.ID] = user
	return nil
}

// UpdateUser 更新用户
func (cm *ConfigManager) UpdateUser(user *UserConfig) error {
	if _, ok := cm.users[user.ID]; !ok {
		return fmt.Errorf("user %s not found", user.ID)
	}

	// 如果密码被修改，重新加密
	existingUser, _ := cm.GetUser(user.ID)
	if user.Password != existingUser.Password {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user.Password = string(hashedPassword)
	}

	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	userDir := filepath.Join(execDir, "configs", "users")
	path := filepath.Join(userDir, user.ID+".yaml")
	user.UpdatedAt = time.Now()
	content, err := yaml.Marshal(user)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.users[user.ID] = user
	return nil
}

// DeleteUser 删除用户
func (cm *ConfigManager) DeleteUser(id string) error {
	if _, ok := cm.users[id]; !ok {
		return fmt.Errorf("user %s not found", id)
	}

	// 不允许删除管理员用户
	if id == "admin" {
		return fmt.Errorf("cannot delete admin user")
	}

	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	userDir := filepath.Join(execDir, "configs", "users")
	path := filepath.Join(userDir, id+".yaml")
	if err := os.Remove(path); err != nil {
		return err
	}

	delete(cm.users, id)
	return nil
}

// loadAccounts 加载账户配置
func (cm *ConfigManager) loadAccounts() error {
	// 如果数据库管理器存在，从数据库加载
	if cm.dbManager != nil {
		accounts, err := cm.dbManager.GetAllAccounts()
		if err != nil {
			return err
		}

		// 清空当前账户映射
		cm.accounts = make(map[string]*AccountConfig)

		// 将从数据库加载的账户添加到映射中
		for _, account := range accounts {
			cm.accounts[account.ID] = account
		}

		return nil
	}

	// 否则，从文件系统加载
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	accountDir := filepath.Join(execDir, "configs", "accounts")
	files, err := os.ReadDir(accountDir)
	if err != nil {
		if os.IsNotExist(err) {
			// 账户目录不存在，创建空目录
			if err := os.MkdirAll(accountDir, 0755); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(accountDir, file.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var account AccountConfig
		if err := yaml.Unmarshal(content, &account); err != nil {
			return fmt.Errorf("unmarshal account config %s failed: %v", path, err)
		}

		cm.accounts[account.ID] = &account
	}

	return nil
}

// GetAllAccounts 获取所有账户
func (cm *ConfigManager) GetAllAccounts() []*AccountConfig {
	var accounts []*AccountConfig
	for _, account := range cm.accounts {
		accounts = append(accounts, account)
	}
	return accounts
}

// GetAccount 根据ID获取账户
func (cm *ConfigManager) GetAccount(id string) (*AccountConfig, bool) {
	account, ok := cm.accounts[id]
	return account, ok
}



// AddAccount 添加账户
func (cm *ConfigManager) AddAccount(account *AccountConfig) error {
	if account.ID == "" {
		return fmt.Errorf("account ID cannot be empty")
	}

	// 检查账户ID是否已经存在
	if _, ok := cm.accounts[account.ID]; ok {
		return fmt.Errorf("account %s already exists", account.ID)
	}

	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		account.CreatedAt = time.Now()
		account.UpdatedAt = time.Now()

		if err := cm.dbManager.SaveAccount(account); err != nil {
			return err
		}

		cm.accounts[account.ID] = account
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	accountDir := filepath.Join(execDir, "configs", "accounts")
	if err := os.MkdirAll(accountDir, 0755); err != nil {
		return err
	}

	account.CreatedAt = time.Now()
	account.UpdatedAt = time.Now()

	path := filepath.Join(accountDir, account.ID+".yaml")
	content, err := yaml.Marshal(account)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.accounts[account.ID] = account
	return nil
}

// UpdateAccount 更新账户
func (cm *ConfigManager) UpdateAccount(account *AccountConfig) error {
	if _, ok := cm.accounts[account.ID]; !ok {
		return fmt.Errorf("account %s not found", account.ID)
	}

	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		account.UpdatedAt = time.Now()

		if err := cm.dbManager.SaveAccount(account); err != nil {
			return err
		}

		cm.accounts[account.ID] = account
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	accountDir := filepath.Join(execDir, "configs", "accounts")
	path := filepath.Join(accountDir, account.ID+".yaml")
	account.UpdatedAt = time.Now()
	content, err := yaml.Marshal(account)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.accounts[account.ID] = account
	return nil
}

// DeleteAccount 删除账户
func (cm *ConfigManager) DeleteAccount(id string) error {
	if _, ok := cm.accounts[id]; !ok {
		return fmt.Errorf("account %s not found", id)
	}

	// 如果数据库管理器存在，使用数据库存储
	if cm.dbManager != nil {
		if err := cm.dbManager.DeleteAccount(id); err != nil {
			return err
		}

		delete(cm.accounts, id)
		return nil
	}

	// 否则，使用文件系统存储
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	accountDir := filepath.Join(execDir, "configs", "accounts")
	path := filepath.Join(accountDir, id+".yaml")
	if err := os.Remove(path); err != nil {
		return err
	}

	delete(cm.accounts, id)
	return nil
}

// Reload 重新加载配置
func (cm *ConfigManager) Reload() error {
	// 先清空现有配置
	cm.domains = make(map[string]*DomainConfig)
	cm.servers = make(map[string]*ServerConfig)
	cm.dnsConfigs = make(map[string]*DNSConfig)
	cm.users = make(map[string]*UserConfig)
	cm.accounts = make(map[string]*AccountConfig)

	if err := cm.loadDomains(); err != nil {
		return err
	}
	if err := cm.loadServers(); err != nil {
		return err
	}
	if err := cm.loadDNS(); err != nil {
		return err
	}
	if err := cm.loadCheckConfig(); err != nil {
		return err
	}
	if err := cm.loadUsers(); err != nil {
		return err
	}
	if err := cm.loadAccounts(); err != nil {
		return err
	}

	return nil
}
