@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

echo ===================================
echo 微软奖励脚本环境自动安装程序
echo ===================================
echo.

:: 检查Node.js是否已安装
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Node.js未安装，正在下载并安装...
    
    :: 创建临时目录
    mkdir %TEMP%\node-install >nul 2>nul
    cd %TEMP%\node-install
    
    :: 下载Node.js安装程序
    echo 正在下载Node.js安装程序...
    powershell -Command "(New-Object System.Net.WebClient).DownloadFile('https://npmmirror.com/mirrors/node/v24.13.0/node-v24.13.0-x64.msi', 'node-installer.msi')"
    
    :: 安装Node.js
    echo 正在安装Node.js...
    start /wait msiexec /i node-installer.msi /quiet /norestart
    
    :: 清理临时文件
    cd %~dp0
    rmdir /s /q %TEMP%\node-install >nul 2>nul
    

    :: 检查Node.js是否可用
    where node >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo 警告：Node.js安装完成，但环境变量可能未生效。
        echo 请关闭此窗口，重新打开命令提示符，然后运行setup.bat继续安装。
        pause
        exit
    )
) else (
    echo Node.js已安装，版本信息：
    node -v
)

:: 检查npm是否已安装
where npm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo npm更新...
    call npm install -g npm
    echo npm未安装，正在安装...

    if %ERRORLEVEL% neq 0 (
        echo 安装npm失败，请检查网络连接或手动安装。
        pause
        exit /b 1
    )
) else (
    echo npm已安装
)

echo.


:: 检查并准备账户配置文件
if not exist "src\accounts.json" (
    if exist "src\accounts.example.json" (
        echo 正在创建账户配置文件...
        copy "src\accounts.example.json" "src\accounts.json"
        echo 已创建accounts.json文件，请在运行脚本前编辑此文件添加您的账户信息。
    ) else (
        echo 警告：未找到accounts.example.json文件，请手动创建accounts.json文件。
    )
) else (
    echo accounts.json文件已存在。
)

:: 检查并准备全局配置文件
if not exist "src\config.json" (
    if exist "src\config.example.json" (
        echo 正在创建全局配置文件...
        copy "src\config.example.json" "src\config.json"
        echo 已创建config.json文件，请按需修改该配置文件。
    ) else (
        echo 警告：未找到config.example.json文件，请手动创建config.json文件。
    )
) else (
    echo config.json文件已存在。
)
:: 预构建项目
echo 正在预构建项目...
call npm run pre-build
if %ERRORLEVEL% neq 0 (
    echo 预构建项目失败，请检查错误信息。
    pause
    exit /b 1
)

:: 构建项目
echo 正在构建项目...
call npm run build
if %ERRORLEVEL% neq 0 (
    echo 构建项目失败，请检查错误信息。
    pause
    exit /b 1
)

:: 检查构建产物
if exist "dist\accounts.json" (
    echo 已生成dist\accounts.json，请编辑此文件添加您的账户信息。
) else (
    echo 警告：未生成dist\accounts.json文件，请检查构建是否成功。
)
if exist "dist\config.json" (
    echo 已生成dist\config.json，请按需修改该配置文件。
) else (
    echo 警告：未生成dist\config.json文件，请检查构建是否成功。
)

echo.
echo ===================================
echo 安装完成！
echo 后续步骤：
echo 1. dist\accounts.json文件添加您的账户信息
echo 2. 检查并按需修改dist\config.json配置文件
echo 3. 执行终端命令：npm start，或运行脚本：run.bat
echo ===================================

pause
