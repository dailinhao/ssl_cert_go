package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"
)

// DBConfig 数据库配置
type DBConfig struct {
	Type     string `yaml:"type"`     // sqlite, mysql, postgresql
	Host     string `yaml:"host"`     // 数据库主机
	Port     int    `yaml:"port"`     // 数据库端口
	User     string `yaml:"user"`     // 数据库用户名
	Password string `yaml:"password"` // 数据库密码
	Database string `yaml:"database"` // 数据库名称
	Path     string `yaml:"path"`     // SQLite 数据库文件路径
}

// LoadDBConfig 加载数据库配置
func LoadDBConfig() (*DBConfig, error) {
	// 加载 .env 文件
	execDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	envPath := filepath.Join(execDir, ".env")
	if _, err := os.Stat(envPath); err == nil {
		if err := godotenv.Load(envPath); err != nil {
			fmt.Printf("Warning: Error loading .env file: %v\n", err)
		}
	}

	// 从环境变量中读取配置
	dbType := getEnv("DB_TYPE", "")
	if dbType == "" {
		dbType = getEnv("DB_CONNECTION", "sqlite")
	}

	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnvAsInt("DB_PORT", 3306)
	dbUser := getEnv("DB_USER", "")
	if dbUser == "" {
		dbUser = getEnv("DB_USERNAME", "root")
	}

	dbPassword := getEnv("DB_PASSWORD", "123456")
	dbName := getEnv("DB_NAME", "")
	if dbName == "" {
		dbName = getEnv("DB_DATABASE", "cert_manager")
	}

	config := &DBConfig{
		Type:     dbType,
		Host:     dbHost,
		Port:     dbPort,
		User:     dbUser,
		Password: dbPassword,
		Database: dbName,
		Path:     getEnv("DB_PATH", "./cert-manager.db"),
	}

	// 验证配置
	if config.Type == "" {
		config.Type = "sqlite"
	}

	if config.Type == "sqlite" && config.Path == "" {
		config.Path = "./cert-manager.db"
	}

	return config, nil
}

// getEnv 获取环境变量，如果不存在则返回默认值
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsInt 获取环境变量并转换为整数，如果不存在或转换失败则返回默认值
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

// getEnvAsBool 获取环境变量并转换为布尔值，如果不存在或转换失败则返回默认值
func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

// ServerEnvConfig 服务器环境配置
type ServerEnvConfig struct {
	Host      string
	Port      int
	HTTPS     bool
	CertPath  string
	KeyPath   string
	FrontendURL string
}

// LoadServerConfig 加载服务器配置
func LoadServerConfig() *ServerEnvConfig {
	// 直接返回端口 8094
	return &ServerEnvConfig{
		Host:      "0.0.0.0",
		Port:      8094,
		HTTPS:     false,
		CertPath:  "",
		KeyPath:   "",
		FrontendURL: "http://localhost:3000",
	}
}

// CertConfig 证书配置
type CertConfig struct {
	StorePath   string
	RenewDays   int
	ScriptPath  string
	ConfigPath  string
}

// LoadCertConfig 加载证书配置
func LoadCertConfig() *CertConfig {
	return &CertConfig{
		StorePath:   "./certs.backup",
		RenewDays:   30,
		ScriptPath:  "",
		ConfigPath:  "",
	}
}

// GetDatabaseManager 根据配置获取数据库管理器
func GetDatabaseManager() (DatabaseInterface, error) {
	// 加载数据库配置
	config, err := LoadDBConfig()
	if err != nil {
		return nil, err
	}

	// 根据配置创建数据库管理器
	if config.Type == "sqlite" {
		return NewDatabaseManager(config.Path)
	} else if config.Type == "mysql" {
		// 这里可以添加MySQL数据库管理器的创建逻辑
		// 暂时返回SQLite数据库管理器作为默认
		return NewDatabaseManager("./cert-manager.db")
	} else {
		// 其他数据库类型暂时返回SQLite数据库管理器
		return NewDatabaseManager("./cert-manager.db")
	}
}
