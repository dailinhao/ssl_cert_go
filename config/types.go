package config

import "time"

// DomainConfig 单个域名配置(不修改代码，只改配置文件)
type DomainConfig struct {
	ID             string                 `yaml:"id" json:"id"`
	Domain         string                 `yaml:"domain" json:"domain"`
	SubDomains     []string               `yaml:"sub_domains" json:"sub_domains"`
	DNSProvider    DNSProviderConfig      `yaml:"dns_provider" json:"dns_provider"`
	Deployments    []DeploymentConfig     `yaml:"deployments" json:"deployments"`
	SSLConfig      SSLConfig              `yaml:"ssl_config" json:"ssl_config"`
	AutoRenew      bool                   `yaml:"auto_renew" json:"auto_renew"`
	RenewDays      int                    `yaml:"renew_days_before" json:"renew_days_before"` // 到期前N天续期
	PurchaseCert   bool                   `yaml:"purchase_cert" json:"purchase_cert"`           // 是否购买证书
	CertType       string                 `yaml:"cert_type" json:"cert_type"`                   // 证书类型: official, test
	Business       string                 `yaml:"business" json:"business"`                     // 业务
	CloudVendor    string                 `yaml:"cloud_vendor" json:"cloud_vendor"`             // 云厂商
	Account        string                 `yaml:"account" json:"account"`                       // 账号
	AccountID      string                 `yaml:"account_id" json:"account_id"`                 // 绑定的账户ID
	Remark         string                 `yaml:"remark" json:"remark"`                         // 备注
	DomainExpiry   *time.Time             `yaml:"domain_expiry,omitempty" json:"domain_expiry,omitempty"` // 域名到期日期
	DeploymentType string                 `yaml:"deployment_type,omitempty" json:"deployment_type,omitempty"` // 部署类型
	SLBConfig      *SLBDeployConfig      `yaml:"slb_config,omitempty" json:"slb_config,omitempty"`         // SLB部署配置
	ACKConfig      *ACKDeployConfig       `yaml:"ack_config,omitempty" json:"ack_config,omitempty"`         // ACK部署配置
	Extra          map[string]interface{} `yaml:"extra,omitempty" json:"extra"`                // 扩展字段
}

type DNSProviderConfig struct {
	Type        string            `yaml:"type" json:"type"` // dnspod, aliyun, volcengine, aws, cloudflare, godaddy
	Region      string            `yaml:"region,omitempty" json:"region,omitempty"`
	Credentials map[string]string `yaml:"credentials" json:"-"` // API密钥(加密存储)
}

type DeploymentConfig struct {
	Type       string            `yaml:"type" json:"type"` // ssh, k8s, s3, webhook, slb
	ServerID   string            `yaml:"server_id,omitempty" json:"server_id,omitempty"`
	TargetPath string            `yaml:"target_path" json:"target_path"`
	Commands   []string          `yaml:"commands,omitempty" json:"commands,omitempty"`
	K8sConfig  *K8sDeployConfig  `yaml:"k8s_config,omitempty" json:"k8s_config,omitempty"`
	S3Config   *S3DeployConfig   `yaml:"s3_config,omitempty" json:"s3_config,omitempty"`
	SLBConfig  *SLBDeployConfig  `yaml:"slb_config,omitempty" json:"slb_config,omitempty"`
	Webhook    string            `yaml:"webhook,omitempty" json:"webhook,omitempty"`
}

type K8sDeployConfig struct {
	Namespace   string `yaml:"namespace" json:"namespace"`
	SecretName  string `yaml:"secret_name" json:"secret_name"`
	ConfigMap   string `yaml:"config_map,omitempty" json:"config_map,omitempty"`
	RestartPods []string `yaml:"restart_pods,omitempty" json:"restart_pods,omitempty"`
}

type S3DeployConfig struct {
	Bucket     string `yaml:"bucket" json:"bucket"`
	Region     string `yaml:"region" json:"region"`
	AccessKey  string `yaml:"access_key" json:"-"`
	SecretKey  string `yaml:"secret_key" json:"-"`
	ObjectPath string `yaml:"object_path" json:"object_path"`
}

type SLBDeployConfig struct {
	SLBID      string `yaml:"slb_id" json:"slb_id"`
	Region     string `yaml:"region" json:"region"`
	Protocol   string `yaml:"protocol" json:"protocol"` // HTTP, HTTPS
	Port       int    `yaml:"port" json:"port"`
	CertificateID string `yaml:"certificate_id" json:"certificate_id"`
	AccountID  string `yaml:"account_id" json:"account_id"` // 绑定的账户ID
	AccessKey  string `yaml:"access_key" json:"-"`
	SecretKey  string `yaml:"secret_key" json:"-"`
}

// ACKDeployConfig ACK部署配置
type ACKDeployConfig struct {
	ClusterID    string `yaml:"cluster_id" json:"cluster_id"`
	Region       string `yaml:"region" json:"region"`
	Namespace    string `yaml:"namespace" json:"namespace"`
	SecretName   string `yaml:"secret_name" json:"secret_name"`
	ConfigMap    string `yaml:"config_map,omitempty" json:"config_map,omitempty"`
	RestartPods  []string `yaml:"restart_pods,omitempty" json:"restart_pods,omitempty"`
	AccountID    string `yaml:"account_id" json:"account_id"` // 绑定的账户ID
}

// AccountConfig 账户配置
type AccountConfig struct {
	ID        string            `yaml:"id" json:"id"`
	Name      string            `yaml:"name" json:"name"`
	CloudVendor string          `yaml:"cloud_vendor" json:"cloud_vendor"`
	Region    string            `yaml:"region" json:"region"`
	AccessKey string            `yaml:"access_key" json:"access_key"` // 从JSON请求中绑定
	SecretKey string            `yaml:"secret_key" json:"secret_key"` // 从JSON请求中绑定
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	CreatedAt time.Time         `yaml:"created_at" json:"created_at"`
	UpdatedAt time.Time         `yaml:"updated_at" json:"updated_at"`
	Tags      []string          `yaml:"tags" json:"tags"`
	Metadata  map[string]string `yaml:"metadata" json:"metadata"`
}

type SSLConfig struct {
	CA         string   `yaml:"ca" json:"ca"` // letsencrypt, zerossl, google
	KeyType    string   `yaml:"key_type" json:"key_type"` // RSA2048, RSA4096, EC256
	Challenge  string   `yaml:"challenge" json:"challenge"` // dns-01, http-01
	Email      string   `yaml:"email" json:"email"`
	Nameservers []string `yaml:"nameservers,omitempty" json:"nameservers,omitempty"`
}

// ServerConfig 服务器配置(每台服务器不同域名)
type ServerConfig struct {
	ID       string            `yaml:"id" json:"id"`
	Name     string            `yaml:"name" json:"name"`
	Host     string            `yaml:"host" json:"host"`
	Port     int               `yaml:"port" json:"port"`
	User     string            `yaml:"user" json:"user"`
	AuthType string            `yaml:"auth_type" json:"auth_type"` // password, key
	Password string            `yaml:"password,omitempty" json:"password,omitempty"`
	SSHKey   string            `yaml:"ssh_key,omitempty" json:"ssh_key,omitempty"`
	Tags     []string          `yaml:"tags" json:"tags"`
	Metadata map[string]string `yaml:"metadata" json:"metadata"`
}

// Certificate 证书记录
type Certificate struct {
	ID           string    `json:"id"`
	DomainID     string    `json:"domain_id"`
	Domain       string    `json:"domain"`
	CertPEM      string    `json:"-"`
	KeyPEM       string    `json:"-"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SerialNumber string    `json:"serial_number"`
	Status       string    `json:"status"` // active, expired, revoked
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	DeployedTo   []string  `json:"deployed_to"` // 已部署的服务器ID
}

// CheckConfig 定期检测配置
type CheckConfig struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	Interval    string        `yaml:"interval" json:"interval"` // 检测间隔，如 "24h", "1h"
	Checks      []CheckItem   `yaml:"checks" json:"checks"`
	Notifications []NotificationConfig `yaml:"notifications" json:"notifications"` // 通知配置
}

// NotificationConfig 通知配置
type NotificationConfig struct {
	Type        string            `yaml:"type" json:"type"` // dingtalk, wechat
	Webhook     string            `yaml:"webhook" json:"webhook"`
	Secret      string            `yaml:"secret,omitempty" json:"secret,omitempty"`
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	Events      []string          `yaml:"events" json:"events"` // 触发通知的事件类型
	Params      map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// CheckItem 检测项
type CheckItem struct {
	Type        string        `yaml:"type" json:"type"` // cert, server, dns
	Target      string        `yaml:"target" json:"target"` // 目标ID
	Params      map[string]string `yaml:"params" json:"params"`
}

// UserConfig 用户配置
type UserConfig struct {
	ID           string            `yaml:"id" json:"id"`
	Username     string            `yaml:"username" json:"username"`
	Password     string            `yaml:"password" json:"password"` // 加密存储
	Email        string            `yaml:"email" json:"email"`
	Role         string            `yaml:"role" json:"role"` // admin, user
	Permissions  map[string]bool   `yaml:"permissions" json:"permissions"` // 权限配置
	Enabled      bool              `yaml:"enabled" json:"enabled"`
	CreatedAt    time.Time         `yaml:"created_at" json:"created_at"`
	UpdatedAt    time.Time         `yaml:"updated_at" json:"updated_at"`
}

// ConfigManager 配置管理器
type ConfigManager struct {
	domains     map[string]*DomainConfig
	servers     map[string]*ServerConfig
	dnsConfigs  map[string]*DNSConfig
	checkConfig *CheckConfig
	users       map[string]*UserConfig
	accounts    map[string]*AccountConfig
	dbManager   DatabaseInterface
}
