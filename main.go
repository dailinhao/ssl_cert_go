package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"

	"cert-manager/api"
	"cert-manager/config"
	"cert-manager/scheduler"
	"cert-manager/store"
)

func main() {
	// 加载.env文件
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}

	// 加载配置
	certConfig := config.LoadCertConfig()

	// 初始化配置管理器
	cm := config.NewConfigManager()

	// 初始化证书存储
	certStore := store.NewCertStore(certConfig.StorePath)

	// 初始化续期调度器
	renewScheduler := scheduler.NewRenewScheduler(cm, certStore)
	renewScheduler.Start()

	// 初始化定期检测调度器
	checkScheduler := scheduler.NewCheckScheduler(cm)
	checkScheduler.Start()

	// 设置API路由
	router := api.SetupRouter(cm, renewScheduler, certStore)

	// 构建服务器地址
	addr := fmt.Sprintf("%s:%d", "0.0.0.0", 8093)

	// 启动服务器
	log.Printf("HTTP Server starting on %s...", addr)
	if err := http.ListenAndServe(addr, router); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}
