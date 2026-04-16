@echo off

REM 设置构建参数
set GOARCH=amd64
set GOOS=linux

REM 构建可执行文件
echo 正在构建Linux版本的可执行文件...
go build -o cert-manager-linux main.go

if %errorlevel% equ 0 (
    echo 构建成功！
    echo 可执行文件: cert-manager-linux
) else (
    echo 构建失败！
    pause
)
