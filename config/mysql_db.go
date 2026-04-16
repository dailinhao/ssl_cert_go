package config

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLDatabaseManager MySQL 数据库管理器
type MySQLDatabaseManager struct {
	db *sql.DB
}

// 确保 MySQLDatabaseManager 实现了 DatabaseInterface 接口
var _ DatabaseInterface = &MySQLDatabaseManager{}

// NewMySQLDatabaseManager 创建 MySQL 数据库管理器
func NewMySQLDatabaseManager(dsn string) (*MySQLDatabaseManager, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	manager := &MySQLDatabaseManager{db: db}

	if err := manager.initSchema(); err != nil {
		return nil, err
	}

	return manager, nil
}

// initSchema 初始化数据库表结构
func (dm *MySQLDatabaseManager) initSchema() error {
	// 创建域名表
	_, err := dm.db.Exec(`
	CREATE TABLE IF NOT EXISTS domains (
		id VARCHAR(255) PRIMARY KEY,
		domain VARCHAR(255) NOT NULL,
		sub_domains TEXT,
		dns_provider TEXT,
		deployments TEXT,
		ssl_config TEXT,
		auto_renew BOOLEAN DEFAULT false,
		renew_days INTEGER DEFAULT 30,
		purchase_cert BOOLEAN DEFAULT false,
		cert_type VARCHAR(50),
		business VARCHAR(255),
		cloud_vendor VARCHAR(100),
		account VARCHAR(255),
		account_id VARCHAR(255),
		remark TEXT,
		domain_expiry VARCHAR(50),
		deployment_type VARCHAR(100),
		slb_config TEXT,
		ack_config TEXT,
		extra TEXT,
		created_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP,
		updated_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP
	)
	`)
	if err != nil {
		return err
	}

	// 创建服务器表
	_, err = dm.db.Exec(`
	CREATE TABLE IF NOT EXISTS servers (
		id VARCHAR(255) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		host VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		user VARCHAR(255) NOT NULL,
		auth_type VARCHAR(50) NOT NULL,
		password TEXT,
		ssh_key TEXT,
		tags TEXT,
		metadata TEXT,
		created_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP,
		updated_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP
	)
	`)
	if err != nil {
		return err
	}

	// 创建账户表
	_, err = dm.db.Exec(`
	CREATE TABLE IF NOT EXISTS accounts (
		id VARCHAR(255) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		cloud_vendor VARCHAR(100) NOT NULL,
		region VARCHAR(100),
		access_key VARCHAR(255) NOT NULL,
		secret_key VARCHAR(255) NOT NULL,
		enabled BOOLEAN DEFAULT true,
		tags TEXT,
		metadata TEXT,
		created_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP,
		updated_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP
	)
	`)
	if err != nil {
		return err
	}

	// 创建用户表
	_, err = dm.db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(255) PRIMARY KEY,
		username VARCHAR(255) NOT NULL UNIQUE,
		password VARCHAR(255) NOT NULL,
		email VARCHAR(255),
		role VARCHAR(50) DEFAULT 'user',
		permissions TEXT,
		enabled BOOLEAN DEFAULT true,
		created_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP,
		updated_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP
	)
	`)
	if err != nil {
		return err
	}

	// 创建证书表
	_, err = dm.db.Exec(`
	CREATE TABLE IF NOT EXISTS certificates (
		id VARCHAR(255) PRIMARY KEY,
		domain_id VARCHAR(255) NOT NULL,
		domain VARCHAR(255) NOT NULL,
		cert_pem TEXT NOT NULL,
		key_pem TEXT NOT NULL,
		issuer VARCHAR(255),
		not_before VARCHAR(50) NOT NULL,
		not_after VARCHAR(50) NOT NULL,
		serial_number VARCHAR(255),
		status VARCHAR(50) DEFAULT 'active',
		deployed_to TEXT,
		created_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP,
		updated_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (domain_id) REFERENCES domains(id)
	)
	`)
	if err != nil {
		return err
	}

	// 创建检查配置表
	_, err = dm.db.Exec(`
	CREATE TABLE IF NOT EXISTS check_config (
		id INTEGER PRIMARY KEY AUTO_INCREMENT,
		enabled BOOLEAN DEFAULT true,
		interval VARCHAR(50) DEFAULT '24h',
		checks TEXT,
		notifications TEXT,
		updated_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP
	)
	`)
	if err != nil {
		return err
	}

	return nil
}

// Close 关闭数据库连接
func (dm *MySQLDatabaseManager) Close() error {
	return dm.db.Close()
}

// SaveDomain 保存域名配置
func (dm *MySQLDatabaseManager) SaveDomain(domain *DomainConfig) error {
	// 序列化复杂字段
	subDomainsJSON, err := json.Marshal(domain.SubDomains)
	if err != nil {
		return err
	}

	dnsProviderJSON, err := json.Marshal(domain.DNSProvider)
	if err != nil {
		return err
	}

	deploymentsJSON, err := json.Marshal(domain.Deployments)
	if err != nil {
		return err
	}

	sslConfigJSON, err := json.Marshal(domain.SSLConfig)
	if err != nil {
		return err
	}

	var domainExpiry string
	if domain.DomainExpiry != nil {
		domainExpiry = domain.DomainExpiry.Format(time.RFC3339)
	}

	var slbConfigJSON []byte
	if domain.SLBConfig != nil {
		slbConfigJSON, err = json.Marshal(domain.SLBConfig)
		if err != nil {
			return err
		}
	}

	var ackConfigJSON []byte
	if domain.ACKConfig != nil {
		ackConfigJSON, err = json.Marshal(domain.ACKConfig)
		if err != nil {
			return err
		}
	}

	extraJSON, err := json.Marshal(domain.Extra)
	if err != nil {
		return err
	}

	// 检查域名是否存在
	var count int
	err = dm.db.QueryRow("SELECT COUNT(*) FROM domains WHERE id = ?", domain.ID).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		// 更新域名
		_, err = dm.db.Exec(`
		UPDATE domains SET 
			domain = ?, 
			sub_domains = ?, 
			dns_provider = ?, 
			deployments = ?, 
			ssl_config = ?, 
			auto_renew = ?, 
			renew_days = ?, 
			purchase_cert = ?, 
			cert_type = ?, 
			business = ?, 
			cloud_vendor = ?, 
			account = ?, 
			account_id = ?, 
			remark = ?, 
			domain_expiry = ?, 
			deployment_type = ?, 
			slb_config = ?, 
			ack_config = ?, 
			extra = ?, 
			updated_at = ? 
		WHERE id = ?
		`, domain.Domain, string(subDomainsJSON), string(dnsProviderJSON), string(deploymentsJSON), string(sslConfigJSON), domain.AutoRenew, domain.RenewDays, domain.PurchaseCert, domain.CertType, domain.Business, domain.CloudVendor, domain.Account, domain.AccountID, domain.Remark, domainExpiry, domain.DeploymentType, string(slbConfigJSON), string(ackConfigJSON), string(extraJSON), time.Now().Format(time.RFC3339), domain.ID)
	} else {
		// 插入域名
		_, err = dm.db.Exec(`
		INSERT INTO domains (
			id, domain, sub_domains, dns_provider, deployments, ssl_config, 
			auto_renew, renew_days, purchase_cert, cert_type, business, 
			cloud_vendor, account, account_id, remark, domain_expiry, 
			deployment_type, slb_config, ack_config, extra, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, domain.ID, domain.Domain, string(subDomainsJSON), string(dnsProviderJSON), string(deploymentsJSON), string(sslConfigJSON), domain.AutoRenew, domain.RenewDays, domain.PurchaseCert, domain.CertType, domain.Business, domain.CloudVendor, domain.Account, domain.AccountID, domain.Remark, domainExpiry, domain.DeploymentType, string(slbConfigJSON), string(ackConfigJSON), string(extraJSON), time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	}

	return err
}

// GetDomain 获取域名配置
func (dm *MySQLDatabaseManager) GetDomain(id string) (*DomainConfig, error) {
	row := dm.db.QueryRow(`
	SELECT 
		id, domain, sub_domains, dns_provider, deployments, ssl_config, 
		auto_renew, renew_days, purchase_cert, cert_type, business, 
		cloud_vendor, account, account_id, remark, domain_expiry, 
		deployment_type, slb_config, ack_config, extra 
	FROM domains WHERE id = ?
	`, id)

	var domain DomainConfig
	var subDomainsJSON, dnsProviderJSON, deploymentsJSON, sslConfigJSON, domainExpiry, slbConfigJSON, ackConfigJSON, extraJSON string

	err := row.Scan(
		&domain.ID, &domain.Domain, &subDomainsJSON, &dnsProviderJSON, &deploymentsJSON, &sslConfigJSON, 
		&domain.AutoRenew, &domain.RenewDays, &domain.PurchaseCert, &domain.CertType, &domain.Business, 
		&domain.CloudVendor, &domain.Account, &domain.AccountID, &domain.Remark, &domainExpiry, 
		&domain.DeploymentType, &slbConfigJSON, &ackConfigJSON, &extraJSON,
	)

	if err != nil {
		return nil, err
	}

	// 反序列化复杂字段
	if err := json.Unmarshal([]byte(subDomainsJSON), &domain.SubDomains); err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(dnsProviderJSON), &domain.DNSProvider); err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(deploymentsJSON), &domain.Deployments); err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(sslConfigJSON), &domain.SSLConfig); err != nil {
		return nil, err
	}

	if domainExpiry != "" {
		expiry, err := time.Parse(time.RFC3339, domainExpiry)
		if err != nil {
			return nil, err
		}
		domain.DomainExpiry = &expiry
	}

	if slbConfigJSON != "" {
		domain.SLBConfig = &SLBDeployConfig{}
		if err := json.Unmarshal([]byte(slbConfigJSON), domain.SLBConfig); err != nil {
			return nil, err
		}
	}

	if ackConfigJSON != "" {
		domain.ACKConfig = &ACKDeployConfig{}
		if err := json.Unmarshal([]byte(ackConfigJSON), domain.ACKConfig); err != nil {
			return nil, err
		}
	}

	if extraJSON != "" {
		if err := json.Unmarshal([]byte(extraJSON), &domain.Extra); err != nil {
			return nil, err
		}
	}

	return &domain, nil
}

// GetAllDomains 获取所有域名配置
func (dm *MySQLDatabaseManager) GetAllDomains() ([]*DomainConfig, error) {
	rows, err := dm.db.Query(`
	SELECT 
		id, domain, sub_domains, dns_provider, deployments, ssl_config, 
		auto_renew, renew_days, purchase_cert, cert_type, business, 
		cloud_vendor, account, account_id, remark, domain_expiry, 
		deployment_type, slb_config, ack_config, extra 
	FROM domains
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []*DomainConfig
	for rows.Next() {
		var domain DomainConfig
		var subDomainsJSON, dnsProviderJSON, deploymentsJSON, sslConfigJSON, domainExpiry, slbConfigJSON, ackConfigJSON, extraJSON string

		err := rows.Scan(
			&domain.ID, &domain.Domain, &subDomainsJSON, &dnsProviderJSON, &deploymentsJSON, &sslConfigJSON, 
			&domain.AutoRenew, &domain.RenewDays, &domain.PurchaseCert, &domain.CertType, &domain.Business, 
			&domain.CloudVendor, &domain.Account, &domain.AccountID, &domain.Remark, &domainExpiry, 
			&domain.DeploymentType, &slbConfigJSON, &ackConfigJSON, &extraJSON,
		)

		if err != nil {
			return nil, err
		}

		// 反序列化复杂字段
		if err := json.Unmarshal([]byte(subDomainsJSON), &domain.SubDomains); err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(dnsProviderJSON), &domain.DNSProvider); err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(deploymentsJSON), &domain.Deployments); err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(sslConfigJSON), &domain.SSLConfig); err != nil {
			return nil, err
		}

		if domainExpiry != "" {
			expiry, err := time.Parse(time.RFC3339, domainExpiry)
			if err != nil {
				return nil, err
			}
			domain.DomainExpiry = &expiry
		}

		if slbConfigJSON != "" {
			domain.SLBConfig = &SLBDeployConfig{}
			if err := json.Unmarshal([]byte(slbConfigJSON), domain.SLBConfig); err != nil {
				return nil, err
			}
		}

		if ackConfigJSON != "" {
			domain.ACKConfig = &ACKDeployConfig{}
			if err := json.Unmarshal([]byte(ackConfigJSON), domain.ACKConfig); err != nil {
				return nil, err
			}
		}

		if extraJSON != "" {
			if err := json.Unmarshal([]byte(extraJSON), &domain.Extra); err != nil {
				return nil, err
			}
		}

		domains = append(domains, &domain)
	}

	return domains, nil
}

// DeleteDomain 删除域名配置
func (dm *MySQLDatabaseManager) DeleteDomain(id string) error {
	_, err := dm.db.Exec("DELETE FROM domains WHERE id = ?", id)
	return err
}

// SaveServer 保存服务器配置
func (dm *MySQLDatabaseManager) SaveServer(server *ServerConfig) error {
	// 序列化复杂字段
	tagsJSON, err := json.Marshal(server.Tags)
	if err != nil {
		return err
	}

	metadataJSON, err := json.Marshal(server.Metadata)
	if err != nil {
		return err
	}

	// 检查服务器是否存在
	var count int
	err = dm.db.QueryRow("SELECT COUNT(*) FROM servers WHERE id = ?", server.ID).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		// 更新服务器
		_, err = dm.db.Exec(`
		UPDATE servers SET 
			name = ?, 
			host = ?, 
			port = ?, 
			user = ?, 
			auth_type = ?, 
			password = ?, 
			ssh_key = ?, 
			tags = ?, 
			metadata = ?, 
			updated_at = ? 
		WHERE id = ?
		`, server.Name, server.Host, server.Port, server.User, server.AuthType, server.Password, server.SSHKey, string(tagsJSON), string(metadataJSON), time.Now().Format(time.RFC3339), server.ID)
	} else {
		// 插入服务器
		_, err = dm.db.Exec(`
		INSERT INTO servers (
			id, name, host, port, user, auth_type, password, ssh_key, tags, metadata, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, server.ID, server.Name, server.Host, server.Port, server.User, server.AuthType, server.Password, server.SSHKey, string(tagsJSON), string(metadataJSON), time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	}

	return err
}

// GetServer 获取服务器配置
func (dm *MySQLDatabaseManager) GetServer(id string) (*ServerConfig, error) {
	row := dm.db.QueryRow(`
	SELECT 
		id, name, host, port, user, auth_type, password, ssh_key, tags, metadata 
	FROM servers WHERE id = ?
	`, id)

	var server ServerConfig
	var tagsJSON, metadataJSON string

	err := row.Scan(
		&server.ID, &server.Name, &server.Host, &server.Port, &server.User, &server.AuthType, &server.Password, &server.SSHKey, &tagsJSON, &metadataJSON,
	)

	if err != nil {
		return nil, err
	}

	// 反序列化复杂字段
	if err := json.Unmarshal([]byte(tagsJSON), &server.Tags); err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(metadataJSON), &server.Metadata); err != nil {
		return nil, err
	}

	return &server, nil
}

// GetAllServers 获取所有服务器配置
func (dm *MySQLDatabaseManager) GetAllServers() ([]*ServerConfig, error) {
	rows, err := dm.db.Query(`
	SELECT 
		id, name, host, port, user, auth_type, password, ssh_key, tags, metadata 
	FROM servers
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []*ServerConfig
	for rows.Next() {
		var server ServerConfig
		var tagsJSON, metadataJSON string

		err := rows.Scan(
			&server.ID, &server.Name, &server.Host, &server.Port, &server.User, &server.AuthType, &server.Password, &server.SSHKey, &tagsJSON, &metadataJSON,
		)

		if err != nil {
			return nil, err
		}

		// 反序列化复杂字段
		if err := json.Unmarshal([]byte(tagsJSON), &server.Tags); err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(metadataJSON), &server.Metadata); err != nil {
			return nil, err
		}

		servers = append(servers, &server)
	}

	return servers, nil
}

// DeleteServer 删除服务器配置
func (dm *MySQLDatabaseManager) DeleteServer(id string) error {
	_, err := dm.db.Exec("DELETE FROM servers WHERE id = ?", id)
	return err
}

// SaveAccount 保存账户配置
func (dm *MySQLDatabaseManager) SaveAccount(account *AccountConfig) error {
	// 序列化复杂字段
	tagsJSON, err := json.Marshal(account.Tags)
	if err != nil {
		return err
	}

	metadataJSON, err := json.Marshal(account.Metadata)
	if err != nil {
		return err
	}

	// 检查账户是否存在
	var count int
	err = dm.db.QueryRow("SELECT COUNT(*) FROM accounts WHERE id = ?", account.ID).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		// 更新账户
		_, err = dm.db.Exec(`
		UPDATE accounts SET 
			name = ?, 
			cloud_vendor = ?, 
			region = ?, 
			access_key = ?, 
			secret_key = ?, 
			enabled = ?, 
			tags = ?, 
			metadata = ?, 
			updated_at = ? 
		WHERE id = ?
		`, account.Name, account.CloudVendor, account.Region, account.AccessKey, account.SecretKey, account.Enabled, string(tagsJSON), string(metadataJSON), time.Now().Format(time.RFC3339), account.ID)
	} else {
		// 插入账户
		_, err = dm.db.Exec(`
		INSERT INTO accounts (
			id, name, cloud_vendor, region, access_key, secret_key, enabled, tags, metadata, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, account.ID, account.Name, account.CloudVendor, account.Region, account.AccessKey, account.SecretKey, account.Enabled, string(tagsJSON), string(metadataJSON), time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	}

	return err
}

// GetAccount 获取账户配置
func (dm *MySQLDatabaseManager) GetAccount(id string) (*AccountConfig, error) {
	row := dm.db.QueryRow(`
	SELECT 
		id, name, cloud_vendor, region, access_key, secret_key, enabled, tags, metadata 
	FROM accounts WHERE id = ?
	`, id)

	var account AccountConfig
	var tagsJSON, metadataJSON string

	err := row.Scan(
		&account.ID, &account.Name, &account.CloudVendor, &account.Region, &account.AccessKey, &account.SecretKey, &account.Enabled, &tagsJSON, &metadataJSON,
	)

	if err != nil {
		return nil, err
	}

	// 反序列化复杂字段
	if err := json.Unmarshal([]byte(tagsJSON), &account.Tags); err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(metadataJSON), &account.Metadata); err != nil {
		return nil, err
	}

	return &account, nil
}

// GetAllAccounts 获取所有账户配置
func (dm *MySQLDatabaseManager) GetAllAccounts() ([]*AccountConfig, error) {
	rows, err := dm.db.Query(`
	SELECT 
		id, name, cloud_vendor, region, access_key, secret_key, enabled, tags, metadata 
	FROM accounts
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*AccountConfig
	for rows.Next() {
		var account AccountConfig
		var tagsJSON, metadataJSON string

		err := rows.Scan(
			&account.ID, &account.Name, &account.CloudVendor, &account.Region, &account.AccessKey, &account.SecretKey, &account.Enabled, &tagsJSON, &metadataJSON,
		)

		if err != nil {
			return nil, err
		}

		// 反序列化复杂字段
		if err := json.Unmarshal([]byte(tagsJSON), &account.Tags); err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(metadataJSON), &account.Metadata); err != nil {
			return nil, err
		}

		accounts = append(accounts, &account)
	}

	return accounts, nil
}

// DeleteAccount 删除账户配置
func (dm *MySQLDatabaseManager) DeleteAccount(id string) error {
	_, err := dm.db.Exec("DELETE FROM accounts WHERE id = ?", id)
	return err
}

// SaveUser 保存用户配置
func (dm *MySQLDatabaseManager) SaveUser(user *UserConfig) error {
	// 序列化复杂字段
	permissionsJSON, err := json.Marshal(user.Permissions)
	if err != nil {
		return err
	}

	// 检查用户是否存在
	var count int
	err = dm.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", user.ID).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		// 更新用户
		_, err = dm.db.Exec(`
		UPDATE users SET 
			username = ?, 
			password = ?, 
			email = ?, 
			role = ?, 
			permissions = ?, 
			enabled = ?, 
			updated_at = ? 
		WHERE id = ?
		`, user.Username, user.Password, user.Email, user.Role, string(permissionsJSON), user.Enabled, time.Now().Format(time.RFC3339), user.ID)
	} else {
		// 插入用户
		_, err = dm.db.Exec(`
		INSERT INTO users (
			id, username, password, email, role, permissions, enabled, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, user.ID, user.Username, user.Password, user.Email, user.Role, string(permissionsJSON), user.Enabled, time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	}

	return err
}

// GetUser 获取用户配置
func (dm *MySQLDatabaseManager) GetUser(id string) (*UserConfig, error) {
	row := dm.db.QueryRow(`
	SELECT 
		id, username, password, email, role, permissions, enabled 
	FROM users WHERE id = ?
	`, id)

	var user UserConfig
	var permissionsJSON string

	err := row.Scan(
		&user.ID, &user.Username, &user.Password, &user.Email, &user.Role, &permissionsJSON, &user.Enabled,
	)

	if err != nil {
		return nil, err
	}

	// 反序列化复杂字段
	if err := json.Unmarshal([]byte(permissionsJSON), &user.Permissions); err != nil {
		return nil, err
	}

	return &user, nil
}

// GetAllUsers 获取所有用户配置
func (dm *MySQLDatabaseManager) GetAllUsers() ([]*UserConfig, error) {
	rows, err := dm.db.Query(`
	SELECT 
		id, username, password, email, role, permissions, enabled 
	FROM users
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*UserConfig
	for rows.Next() {
		var user UserConfig
		var permissionsJSON string

		err := rows.Scan(
			&user.ID, &user.Username, &user.Password, &user.Email, &user.Role, &permissionsJSON, &user.Enabled,
		)

		if err != nil {
			return nil, err
		}

		// 反序列化复杂字段
		if err := json.Unmarshal([]byte(permissionsJSON), &user.Permissions); err != nil {
			return nil, err
		}

		users = append(users, &user)
	}

	return users, nil
}

// DeleteUser 删除用户配置
func (dm *MySQLDatabaseManager) DeleteUser(id string) error {
	_, err := dm.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// SaveCertificate 保存证书记录
func (dm *MySQLDatabaseManager) SaveCertificate(cert *Certificate) error {
	// 序列化复杂字段
	deployedToJSON, err := json.Marshal(cert.DeployedTo)
	if err != nil {
		return err
	}

	// 检查证书是否存在
	var count int
	err = dm.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE id = ?", cert.ID).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		// 更新证书
		_, err = dm.db.Exec(`
		UPDATE certificates SET 
			domain_id = ?, 
			domain = ?, 
			cert_pem = ?, 
			key_pem = ?, 
			issuer = ?, 
			not_before = ?, 
			not_after = ?, 
			serial_number = ?, 
			status = ?, 
			deployed_to = ?, 
			updated_at = ? 
		WHERE id = ?
		`, cert.DomainID, cert.Domain, cert.CertPEM, cert.KeyPEM, cert.Issuer, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), cert.SerialNumber, cert.Status, string(deployedToJSON), time.Now().Format(time.RFC3339), cert.ID)
	} else {
		// 插入证书
		_, err = dm.db.Exec(`
		INSERT INTO certificates (
			id, domain_id, domain, cert_pem, key_pem, issuer, not_before, not_after, serial_number, status, deployed_to, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, cert.ID, cert.DomainID, cert.Domain, cert.CertPEM, cert.KeyPEM, cert.Issuer, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), cert.SerialNumber, cert.Status, string(deployedToJSON), time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	}

	return err
}

// GetCertificate 获取证书记录
func (dm *MySQLDatabaseManager) GetCertificate(id string) (*Certificate, error) {
	row := dm.db.QueryRow(`
	SELECT 
		id, domain_id, domain, cert_pem, key_pem, issuer, not_before, not_after, serial_number, status, deployed_to 
	FROM certificates WHERE id = ?
	`, id)

	var cert Certificate
	var notBeforeStr, notAfterStr, deployedToJSON string

	err := row.Scan(
		&cert.ID, &cert.DomainID, &cert.Domain, &cert.CertPEM, &cert.KeyPEM, &cert.Issuer, &notBeforeStr, &notAfterStr, &cert.SerialNumber, &cert.Status, &deployedToJSON,
	)

	if err != nil {
		return nil, err
	}

	// 解析时间字段
	notBefore, err := time.Parse(time.RFC3339, notBeforeStr)
	if err != nil {
		return nil, err
	}
	cert.NotBefore = notBefore

	notAfter, err := time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		return nil, err
	}
	cert.NotAfter = notAfter

	// 反序列化复杂字段
	if err := json.Unmarshal([]byte(deployedToJSON), &cert.DeployedTo); err != nil {
		return nil, err
	}

	return &cert, nil
}

// GetAllCertificates 获取所有证书记录
func (dm *MySQLDatabaseManager) GetAllCertificates() ([]*Certificate, error) {
	rows, err := dm.db.Query(`
	SELECT 
		id, domain_id, domain, cert_pem, key_pem, issuer, not_before, not_after, serial_number, status, deployed_to 
	FROM certificates
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*Certificate
	for rows.Next() {
		var cert Certificate
		var notBeforeStr, notAfterStr, deployedToJSON string

		err := rows.Scan(
			&cert.ID, &cert.DomainID, &cert.Domain, &cert.CertPEM, &cert.KeyPEM, &cert.Issuer, &notBeforeStr, &notAfterStr, &cert.SerialNumber, &cert.Status, &deployedToJSON,
		)

		if err != nil {
			return nil, err
		}

		// 解析时间字段
		notBefore, err := time.Parse(time.RFC3339, notBeforeStr)
		if err != nil {
			return nil, err
		}
		cert.NotBefore = notBefore

		notAfter, err := time.Parse(time.RFC3339, notAfterStr)
		if err != nil {
			return nil, err
		}
		cert.NotAfter = notAfter

		// 反序列化复杂字段
		if err := json.Unmarshal([]byte(deployedToJSON), &cert.DeployedTo); err != nil {
			return nil, err
		}

		certificates = append(certificates, &cert)
	}

	return certificates, nil
}

// DeleteCertificate 删除证书记录
func (dm *MySQLDatabaseManager) DeleteCertificate(id string) error {
	_, err := dm.db.Exec("DELETE FROM certificates WHERE id = ?", id)
	return err
}

// SaveCheckConfig 保存检查配置
func (dm *MySQLDatabaseManager) SaveCheckConfig(config *CheckConfig) error {
	// 序列化复杂字段
	checksJSON, err := json.Marshal(config.Checks)
	if err != nil {
		return err
	}

	notificationsJSON, err := json.Marshal(config.Notifications)
	if err != nil {
		return err
	}

	// 检查检查配置是否存在
	var count int
	err = dm.db.QueryRow("SELECT COUNT(*) FROM check_config WHERE id = 1").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		// 更新检查配置
		_, err = dm.db.Exec(`
		UPDATE check_config SET 
			enabled = ?, 
			interval = ?, 
			checks = ?, 
			notifications = ?, 
			updated_at = ? 
		WHERE id = 1
		`, config.Enabled, config.Interval, string(checksJSON), string(notificationsJSON), time.Now().Format(time.RFC3339))
	} else {
		// 插入检查配置
		_, err = dm.db.Exec(`
		INSERT INTO check_config (
			id, enabled, interval, checks, notifications, updated_at
		) VALUES (?, ?, ?, ?, ?, ?)
		`, 1, config.Enabled, config.Interval, string(checksJSON), string(notificationsJSON), time.Now().Format(time.RFC3339))
	}

	return err
}

// GetCheckConfig 获取检查配置
func (dm *MySQLDatabaseManager) GetCheckConfig() (*CheckConfig, error) {
	row := dm.db.QueryRow(`
	SELECT 
		enabled, interval, checks, notifications 
	FROM check_config WHERE id = 1
	`)

	var config CheckConfig
	var checksJSON, notificationsJSON string

	err := row.Scan(
		&config.Enabled, &config.Interval, &checksJSON, &notificationsJSON,
	)

	if err != nil {
		// 如果没有找到检查配置，返回默认配置
		if err == sql.ErrNoRows {
			return &CheckConfig{
				Enabled:  true,
				Interval: "24h",
				Checks: []CheckItem{
					{Type: "cert", Target: "all", Params: map[string]string{}},
					{Type: "server", Target: "all", Params: map[string]string{}},
				},
				Notifications: []NotificationConfig{},
			}, nil
		}
		return nil, err
	}

	// 反序列化复杂字段
	if err := json.Unmarshal([]byte(checksJSON), &config.Checks); err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(notificationsJSON), &config.Notifications); err != nil {
		return nil, err
	}

	return &config, nil
}

// MigrateFromFileSystem 从文件系统迁移数据到数据库
func (dm *MySQLDatabaseManager) MigrateFromFileSystem() error {
	// 加载文件系统中的域名配置
	domains, err := loadDomainsFromFileSystem()
	if err != nil {
		return err
	}

	// 将域名配置导入数据库
	for _, domain := range domains {
		if err := dm.SaveDomain(domain); err != nil {
			return err
		}
	}

	// 加载文件系统中的服务器配置
	servers, err := loadServersFromFileSystem()
	if err != nil {
		return err
	}

	// 将服务器配置导入数据库
	for _, server := range servers {
		if err := dm.SaveServer(server); err != nil {
			return err
		}
	}

	// 加载文件系统中的账户配置
	accounts, err := loadAccountsFromFileSystem()
	if err != nil {
		return err
	}

	// 将账户配置导入数据库
	for _, account := range accounts {
		if err := dm.SaveAccount(account); err != nil {
			return err
		}
	}

	// 加载文件系统中的用户配置
	users, err := loadUsersFromFileSystem()
	if err != nil {
		return err
	}

	// 将用户配置导入数据库
	for _, user := range users {
		if err := dm.SaveUser(user); err != nil {
			return err
		}
	}

	// 加载文件系统中的检查配置
	checkConfig, err := loadCheckConfigFromFileSystem()
	if err != nil {
		return err
	}

	// 将检查配置导入数据库
	if err := dm.SaveCheckConfig(checkConfig); err != nil {
		return err
	}

	return nil
}
