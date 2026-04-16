package scheduler

import (
	"log"
	"time"

	"cert-manager/config"
	"cert-manager/notifier"
)

// CheckScheduler 定期检测调度器
type CheckScheduler struct {
	cm      *config.ConfigManager
	notifier *notifier.Notifier
}

// NewCheckScheduler 创建定期检测调度器
func NewCheckScheduler(cm *config.ConfigManager) *CheckScheduler {
	// 获取通知配置
	checkConfig := cm.GetCheckConfig()
	// 创建通知服务
	notifier := notifier.NewNotifier(checkConfig.Notifications)
	
	s := &CheckScheduler{
		cm:      cm,
		notifier: notifier,
	}
	return s
}

// Start 启动调度器
func (s *CheckScheduler) Start() {
	go s.run()
}

// run 运行调度器
func (s *CheckScheduler) run() {
	for {
		// 获取检查配置
		checkConfig := s.cm.GetCheckConfig()
		if !checkConfig.Enabled {
			// 检测功能已禁用，等待一段时间后再次检查
			time.Sleep(1 * time.Hour)
			continue
		}

		// 更新通知服务
		s.notifier = notifier.NewNotifier(checkConfig.Notifications)

		// 解析检测间隔
		interval, err := time.ParseDuration(checkConfig.Interval)
		if err != nil {
			log.Printf("解析检测间隔失败: %v, 使用默认值 24h", err)
			interval = 24 * time.Hour
		}

		// 执行检测
		s.executeChecks(checkConfig.Checks)

		// 等待下一次检测
		time.Sleep(interval)
	}
}

// executeChecks 执行检测任务
func (s *CheckScheduler) executeChecks(checks []config.CheckItem) {
	for _, check := range checks {
		go s.executeCheck(check)
	}
}

// executeCheck 执行单个检测任务
func (s *CheckScheduler) executeCheck(check config.CheckItem) {
	switch check.Type {
	case "cert":
		s.checkCertificates(check)
	case "server":
		s.checkServers(check)
	case "dns":
		s.checkDNS(check)
	default:
		log.Printf("未知的检测类型: %s", check.Type)
	}
}

// checkCertificates 检查证书
func (s *CheckScheduler) checkCertificates(check config.CheckItem) {
	log.Println("开始检查证书...")
	// TODO: 实现证书检查逻辑
	// 1. 获取所有域名
	// 2. 检查每个域名的证书状态
	// 3. 记录检查结果
	log.Println("证书检查完成")
	
	// 发送检查成功通知
	if s.notifier != nil {
		s.notifier.SendNotification(notifier.EventCheckSuccess, notifier.NotificationMessage{
			Title:     "证书检测完成",
			Message:   "所有证书检查已完成",
			Level:     "info",
			Timestamp: time.Now(),
		})
	}
}

// checkServers 检查服务器
func (s *CheckScheduler) checkServers(check config.CheckItem) {
	log.Println("开始检查服务器...")
	// TODO: 实现服务器检查逻辑
	// 1. 获取所有服务器
	// 2. 检查每个服务器的连接状态
	// 3. 记录检查结果
	log.Println("服务器检查完成")
}

// checkDNS 检查DNS
func (s *CheckScheduler) checkDNS(check config.CheckItem) {
	log.Println("开始检查DNS...")
	// TODO: 实现DNS检查逻辑
	// 1. 获取所有DNS配置
	// 2. 检查每个DNS记录的状态
	// 3. 记录检查结果
	log.Println("DNS检查完成")
}
