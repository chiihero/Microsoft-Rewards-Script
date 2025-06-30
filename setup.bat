@echo off
setlocal enabledelayedexpansion

echo ===================================
echo ΢�����ű������Զ���װ����
echo ===================================
echo.

:: ���Node.js�Ƿ��Ѱ�װ
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Node.jsδ��װ���������ز���װ...
    
    :: ������ʱĿ¼
    mkdir %TEMP%\node-install >nul 2>nul
    cd %TEMP%\node-install
    
    :: ����Node.js��װ����
    echo ��������Node.js��װ����...
    powershell -Command "(New-Object System.Net.WebClient).DownloadFile('https://nodejs.org/dist/v22.16.0/node-v22.16.0-x64.msi', 'node-installer.msi')"
    
    :: ��װNode.js
    echo ���ڰ�װNode.js...
    start /wait msiexec /i node-installer.msi /quiet /norestart
    
    :: ������ʱ�ļ�
    cd %~dp0
    rmdir /s /q %TEMP%\node-install >nul 2>nul
    

    :: ���Node.js�Ƿ����
    where node >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo ���棺Node.js��װ��ɣ���������������δ��Ч��
        echo ��رմ˴��ڣ����´�������ʾ����Ȼ������setup.bat������װ��
        pause
        exit
    )
) else (
    echo Node.js�Ѱ�װ���汾��Ϣ��
    node -v
)

:: ���pnpm�Ƿ��Ѱ�װ
where pnpm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo npm����...
    call npm install -g npm
    echo pnpmδ��װ�����ڰ�װ...
    call npm install -g pnpm
    if %ERRORLEVEL% neq 0 (
        echo ��װpnpmʧ�ܣ������������ӻ��ֶ���װ��
        pause
        exit /b 1
    )
) else (
    echo pnpm�Ѱ�װ
)

echo.

:: ��װ��Ŀ����
echo ���ڰ�װ��Ŀ����...
call pnpm i
if %ERRORLEVEL% neq 0 (
    echo ��װ����ʧ�ܣ������������ӻ��ֶ���װ��
    pause
    exit /b 1
)

:: ��װPlaywright
echo ���ڰ�װPlaywright...
call pnpm exec playwright install msedge
if %ERRORLEVEL% neq 0 (
    echo ��װPlaywrightʧ�ܣ������������ӻ��ֶ���װ��
    pause
    exit /b 1
)

:: ��鲢׼���˻������ļ�
if not exist "src\accounts.json" (
    if exist "src\accounts.example.json" (
        echo ���ڴ����˻������ļ�...
        copy "src\accounts.example.json" "src\accounts.json"
        echo �Ѵ���accounts.json�ļ����������нű�ǰ�༭���ļ���������˻���Ϣ��
    ) else (
        echo ���棺δ�ҵ�accounts.example.json�ļ������ֶ�����accounts.json�ļ���
    )
) else (
    echo accounts.json�ļ��Ѵ��ڡ�
)

:: ������Ŀ
echo ���ڹ�����Ŀ...
call pnpm build
if %ERRORLEVEL% neq 0 (
    echo ������Ŀʧ�ܣ����������Ϣ��
    pause
    exit /b 1
)

:: �޸�run.bat�е�Ŀ¼Ϊ��ǰ��ĿĿ¼
 echo �޸�run.bat�е�Ŀ¼����...
 powershell -Command "(Get-Content 'run.bat') -replace 'cd D:\\project\\HtmlProject\\Microsoft-Rewards-Script', 'cd %%~dp0' | Set-Content 'run.bat'"
 if %ERRORLEVEL% neq 0 (
     echo �޸�run.batʧ�ܣ����ֶ����·�����á�
     pause
     exit /b 1
 )

:: ��������ļ�
if exist "src\config.json" (
    echo config.json�ļ��Ѵ��ڣ���ȷ���Ѱ�������ϲ�ý��������á�
) else (
    echo ���棺δ�ҵ�config.json�ļ�����ȷ�����ļ����ڲ�����ȷ���á�
)

echo.
echo ===================================
echo ��װ��ɣ�
echo �������裺
echo 1. �༭src\accounts.json�ļ���������˻���Ϣ
echo 2. ��鲢�����޸�src\config.json�����ļ�
echo 3. ִ���ն����pnpm start�������нű���run.bat
echo ===================================

pause