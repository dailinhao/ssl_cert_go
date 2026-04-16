package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DNSConfig DNS配置

type DNSConfig struct {
	ID         string            `yaml:"id" json:"ID,omitempty"`
	Domain     string            `yaml:"domain" json:"Domain,omitempty"`
	Provider   string            `yaml:"provider" json:"Provider,omitempty"`
	DNSConfig  map[string]string `yaml:"dns_config" json:"DNSConfig,omitempty"`
	Records    []DNSRecord       `yaml:"records" json:"Records,omitempty"`
	// 为了兼容前端的小写字段名
	DomainLower     string            `yaml:"-" json:"domain"`
	ProviderLower   string            `yaml:"-" json:"provider"`
	DNSConfigLower  map[string]string `yaml:"-" json:"dns_config"`
	AccountID       string            `yaml:"account_id" json:"account_id"`
}

// DNSRecord DNS记录

type DNSRecord struct {
	ID       string `yaml:"id" json:"id"`
	Name     string `yaml:"name" json:"name"`
	Type     string `yaml:"type" json:"type"`
	Value    string `yaml:"value" json:"value"`
	TTL      int    `yaml:"ttl" json:"ttl"`
	Priority int    `yaml:"priority,omitempty" json:"priority,omitempty"`
}

// loadDNS 加载DNS配置
func (cm *ConfigManager) loadDNS() error {
	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	dnsDir := filepath.Join(execDir, "configs", "dns")
	if err := os.MkdirAll(dnsDir, 0755); err != nil {
		return err
	}

	files, err := os.ReadDir(dnsDir)
	if err != nil {
		if os.IsNotExist(err) {
			// DNS目录不存在，创建空目录
			if err := os.MkdirAll(dnsDir, 0755); err != nil {
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

		path := filepath.Join(dnsDir, file.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var dnsConfig DNSConfig
		if err := yaml.Unmarshal(content, &dnsConfig); err != nil {
			return fmt.Errorf("unmarshal dns config %s failed: %v", path, err)
		}

		if dnsConfig.ID == "" {
			dnsConfig.ID = dnsConfig.Domain
		}
		cm.dnsConfigs[dnsConfig.ID] = &dnsConfig
	}

	return nil
}

// GetAllDNS 获取所有DNS配置
func (cm *ConfigManager) GetAllDNS() []*DNSConfig {
	var dnsConfigs []*DNSConfig
	for _, dns := range cm.dnsConfigs {
		dnsConfigs = append(dnsConfigs, dns)
	}
	return dnsConfigs
}

// GetDNS 根据ID获取DNS配置
func (cm *ConfigManager) GetDNS(id string) (*DNSConfig, bool) {
	dns, ok := cm.dnsConfigs[id]
	return dns, ok
}

// AddDNS 添加DNS配置
func (cm *ConfigManager) AddDNS(dnsConfig *DNSConfig) error {
	// 处理前端发送的小写字段名
	if dnsConfig.Domain == "" && dnsConfig.DomainLower != "" {
		dnsConfig.Domain = dnsConfig.DomainLower
	}
	if dnsConfig.Provider == "" && dnsConfig.ProviderLower != "" {
		dnsConfig.Provider = dnsConfig.ProviderLower
	}
	if dnsConfig.DNSConfig == nil && dnsConfig.DNSConfigLower != nil {
		dnsConfig.DNSConfig = dnsConfig.DNSConfigLower
	}
	if dnsConfig.ID == "" {
		dnsConfig.ID = dnsConfig.Domain
	}

	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	dnsDir := filepath.Join(execDir, "configs", "dns")
	if err := os.MkdirAll(dnsDir, 0755); err != nil {
		return err
	}

	path := filepath.Join(dnsDir, dnsConfig.ID+".yaml")
	content, err := yaml.Marshal(dnsConfig)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.dnsConfigs[dnsConfig.ID] = dnsConfig
	return nil
}

// UpdateDNS 更新DNS配置
func (cm *ConfigManager) UpdateDNS(dnsConfig *DNSConfig) error {
	if _, ok := cm.dnsConfigs[dnsConfig.ID]; !ok {
		return fmt.Errorf("dns config %s not found", dnsConfig.ID)
	}

	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	dnsDir := filepath.Join(execDir, "configs", "dns")
	path := filepath.Join(dnsDir, dnsConfig.ID+".yaml")
	content, err := yaml.Marshal(dnsConfig)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		return err
	}

	cm.dnsConfigs[dnsConfig.ID] = dnsConfig
	return nil
}

// DeleteDNS 删除DNS配置
func (cm *ConfigManager) DeleteDNS(id string) error {
	if _, ok := cm.dnsConfigs[id]; !ok {
		return fmt.Errorf("dns config %s not found", id)
	}

	// 获取当前可执行文件的目录
	execDir, err := os.Getwd()
	if err != nil {
		return err
	}
	// 构建绝对路径
	dnsDir := filepath.Join(execDir, "configs", "dns")
	path := filepath.Join(dnsDir, id+".yaml")
	if err := os.Remove(path); err != nil {
		return err
	}

	delete(cm.dnsConfigs, id)
	return nil
}

// AddDNSRecord 添加DNS记录
func (cm *ConfigManager) AddDNSRecord(dnsID string, record *DNSRecord) error {
	dnsConfig, ok := cm.dnsConfigs[dnsID]
	if !ok {
		return fmt.Errorf("dns config %s not found", dnsID)
	}

	if record.ID == "" {
		record.ID = fmt.Sprintf("%s-%s-%s", dnsID, record.Name, record.Type)
	}

	dnsConfig.Records = append(dnsConfig.Records, *record)
	return cm.UpdateDNS(dnsConfig)
}

// UpdateDNSRecord 更新DNS记录
func (cm *ConfigManager) UpdateDNSRecord(dnsID string, record *DNSRecord) error {
	dnsConfig, ok := cm.dnsConfigs[dnsID]
	if !ok {
		return fmt.Errorf("dns config %s not found", dnsID)
	}

	for i, r := range dnsConfig.Records {
		if r.ID == record.ID {
			dnsConfig.Records[i] = *record
			return cm.UpdateDNS(dnsConfig)
		}
	}

	return fmt.Errorf("record %s not found", record.ID)
}

// DeleteDNSRecord 删除DNS记录
func (cm *ConfigManager) DeleteDNSRecord(dnsID string, recordID string) error {
	dnsConfig, ok := cm.dnsConfigs[dnsID]
	if !ok {
		return fmt.Errorf("dns config %s not found", dnsID)
	}

	for i, r := range dnsConfig.Records {
		if r.ID == recordID {
			dnsConfig.Records = append(dnsConfig.Records[:i], dnsConfig.Records[i+1:]...)
			return cm.UpdateDNS(dnsConfig)
		}
	}

	return fmt.Errorf("record %s not found", recordID)
}