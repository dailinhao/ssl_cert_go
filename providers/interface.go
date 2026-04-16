// backend/providers/interface.go
package providers

import (
	"context"
	"fmt"
)

type DNSProvider interface {
	Name() string
	// 添加TXT记录用于DNS-01验证
	AddTXTRecord(ctx context.Context, domain, subdomain, value string, ttl int) error
	// 删除TXT记录
	RemoveTXTRecord(ctx context.Context, domain, subdomain string) error
	// 获取DNS传播状态
	CheckPropagation(ctx context.Context, domain, token string) (bool, error)
}

// ProviderFactory 创建提供商实例
type ProviderFactory func(config map[string]string) (DNSProvider, error)

var providers = make(map[string]ProviderFactory)

func Register(name string, factory ProviderFactory) {
	providers[name] = factory
}

func GetProvider(name string, config map[string]string) (DNSProvider, error) {
	factory, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", name)
	}
	return factory(config)
}