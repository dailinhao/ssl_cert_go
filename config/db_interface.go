package config

// DatabaseInterface 数据库接口
type DatabaseInterface interface {
	// 域名相关操作
	SaveDomain(domain *DomainConfig) error
	GetDomain(id string) (*DomainConfig, error)
	GetAllDomains() ([]*DomainConfig, error)
	DeleteDomain(id string) error

	// 服务器相关操作
	SaveServer(server *ServerConfig) error
	GetServer(id string) (*ServerConfig, error)
	GetAllServers() ([]*ServerConfig, error)
	DeleteServer(id string) error

	// 账户相关操作
	SaveAccount(account *AccountConfig) error
	GetAccount(id string) (*AccountConfig, error)
	GetAllAccounts() ([]*AccountConfig, error)
	DeleteAccount(id string) error

	// 用户相关操作
	SaveUser(user *UserConfig) error
	GetUser(id string) (*UserConfig, error)
	GetAllUsers() ([]*UserConfig, error)
	DeleteUser(id string) error

	// 证书相关操作
	SaveCertificate(cert *Certificate) error
	GetCertificate(id string) (*Certificate, error)
	GetAllCertificates() ([]*Certificate, error)
	DeleteCertificate(id string) error

	// 检查配置相关操作
	SaveCheckConfig(config *CheckConfig) error
	GetCheckConfig() (*CheckConfig, error)

	// 数据迁移操作
	MigrateFromFileSystem() error

	// 关闭数据库连接
	Close() error
}
