#!/bin/bash

# 启动后端服务
echo "启动后端服务..."
cd "$(dirname "$0")"
go run main.go &
BACKEND_PID=$!

# 等待后端服务启动
sleep 3

# 启动前端服务
echo "启动前端服务..."
cd ../ssl-vue
npm run dev &
FRONTEND_PID=$!

echo "服务已启动："
echo "前端：http://localhost:3000"
echo "后端：http://localhost:8080"
echo "按 Ctrl+C 停止所有服务"

# 等待用户中断
wait $BACKEND_PID $FRONTEND_PID
