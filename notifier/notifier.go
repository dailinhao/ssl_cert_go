package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"cert-manager/config"
)

// Notifier 通知服务
type Notifier struct {
	configs []config.NotificationConfig
}

// NewNotifier 创建通知服务
func NewNotifier(configs []config.NotificationConfig) *Notifier {
	return &Notifier{
		configs: configs,
	}
}

// EventType 事件类型
type EventType string

const (
	EventCertExpiring  EventType = "cert_expiring"  // 证书即将到期
	EventCertExpired   EventType = "cert_expired"   // 证书已过期
	EventServerDown    EventType = "server_down"    // 服务器下线
	EventDNSIssue      EventType = "dns_issue"      // DNS问题
	EventCheckFailed   EventType = "check_failed"   // 检测失败
	EventCheckSuccess  EventType = "check_success"  // 检测成功
)

// NotificationMessage 通知消息
type NotificationMessage struct {
	Event     EventType `json:"event"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Level     string    `json:"level"` // info, warning, error
	Timestamp time.Time `json:"timestamp"`
	Details   map[string]string `json:"details,omitempty"`
}

// SendNotification 发送通知
func (n *Notifier) SendNotification(event EventType, message NotificationMessage) error {
	for _, cfg := range n.configs {
		if !cfg.Enabled {
			continue
		}

		// 检查事件类型是否在配置的事件列表中
		eventMatch := false
		for _, e := range cfg.Events {
			if e == string(event) {
				eventMatch = true
				break
			}
		}
		if !eventMatch {
			continue
		}

		switch cfg.Type {
		case "dingtalk":
			if err := n.sendDingTalkNotification(cfg, message); err != nil {
				log.Printf("发送钉钉通知失败: %v", err)
			}
		case "wechat":
			if err := n.sendWechatNotification(cfg, message); err != nil {
				log.Printf("发送企业微信通知失败: %v", err)
			}
		default:
			log.Printf("未知的通知类型: %s", cfg.Type)
		}
	}
	return nil
}

// sendDingTalkNotification 发送钉钉通知
func (n *Notifier) sendDingTalkNotification(cfg config.NotificationConfig, message NotificationMessage) error {
	// 构建钉钉通知消息
	dingMessage := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": message.Title,
			"text": fmt.Sprintf("### %s\n%s\n\n**时间**: %s\n**级别**: %s",
				message.Title, message.Message, message.Timestamp.Format("2006-01-02 15:04:05"), message.Level),
		},
	}

	// 发送请求
	return n.sendHTTPRequest(cfg.Webhook, dingMessage)
}

// sendWechatNotification 发送企业微信通知
func (n *Notifier) sendWechatNotification(cfg config.NotificationConfig, message NotificationMessage) error {
	// 构建企业微信通知消息
	wechatMessage := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": fmt.Sprintf("### %s\n%s\n\n**时间**: %s\n**级别**: %s",
				message.Title, message.Message, message.Timestamp.Format("2006-01-02 15:04:05"), message.Level),
		},
	}

	// 发送请求
	return n.sendHTTPRequest(cfg.Webhook, wechatMessage)
}

// sendHTTPRequest 发送HTTP请求
func (n *Notifier) sendHTTPRequest(webhook string, payload interface{}) error {
	// 序列化payload
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化通知消息失败: %v", err)
	}

	// 解析webhook URL
	parsedURL, err := url.Parse(webhook)
	if err != nil {
		return fmt.Errorf("解析webhook URL失败: %v", err)
	}

	// 创建HTTP请求
	req, err := http.NewRequest("POST", parsedURL.String(), bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送通知请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("通知服务返回错误状态: %d", resp.StatusCode)
	}

	return nil
}
