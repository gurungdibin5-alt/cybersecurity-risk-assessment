# Automated Cybersecurity Risk Assessment Framework - Windows Setup Script
# Run as Administrator

param(
    [switch]$SkipDocker,
    [switch]$SkipJenkins,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 Setting up Cybersecurity Risk Assessment Framework for Windows 11" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to install Chocolatey
function Install-Chocolatey {
    Write-Host "📦 Installing Chocolatey package manager..." -ForegroundColor Yellow
    
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host "✅ Chocolatey already installed" -ForegroundColor Green
        return
    }
    
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    
    # Refresh environment variables
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    Write-Host "✅ Chocolatey installed successfully" -ForegroundColor Green
}

# Function to install Git
function Install-Git {
    Write-Host "📂 Installing Git..." -ForegroundColor Yellow
    
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Host "✅ Git already installed" -ForegroundColor Green
        return
    }
    
    choco install git -y
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    Write-Host "✅ Git installed successfully" -ForegroundColor Green
}

# Function to install Docker Desktop
function Install-Docker {
    if ($SkipDocker) {
        Write-Host "⏭️ Skipping Docker installation" -ForegroundColor Yellow
        return
    }
    
    Write-Host "🐳 Installing Docker Desktop..." -ForegroundColor Yellow
    
    # Check if Docker is already installed
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Write-Host "✅ Docker already installed" -ForegroundColor Green
        return
    }
    
    # Download and install Docker Desktop
    $dockerUrl = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
    $dockerInstaller = "$env:TEMP\DockerDesktopInstaller.exe"
    
    Write-Host "📥 Downloading Docker Desktop..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $dockerUrl -OutFile $dockerInstaller
    
    Write-Host "🔧 Installing Docker Desktop..." -ForegroundColor Yellow
    Start-Process -FilePath $dockerInstaller -ArgumentList "install", "--quiet" -Wait
    
    Remove-Item $dockerInstaller
    
    Write-Host "✅ Docker Desktop installed. Please restart your system and start Docker Desktop manually." -ForegroundColor Green
    Write-Host "⚠️ After restart, ensure WSL 2 is enabled and Docker is running before proceeding." -ForegroundColor Yellow
}

# Function to install Java (required for Jenkins)
function Install-Java {
    Write-Host "☕ Installing Java JDK..." -ForegroundColor Yellow
    
    if (Get-Command java -ErrorAction SilentlyContinue) {
        Write-Host "✅ Java already installed" -ForegroundColor Green
        return
    }
    
    choco install openjdk11 -y
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    Write-Host "✅ Java installed successfully" -ForegroundColor Green
}

# Function to install Jenkins
function Install-Jenkins {
    if ($SkipJenkins) {
        Write-Host "⏭️ Skipping Jenkins installation" -ForegroundColor Yellow
        return
    }
    
    Write-Host "🏗️ Installing Jenkins..." -ForegroundColor Yellow
    
    # Check if Jenkins service exists
    if (Get-Service -Name Jenkins -ErrorAction SilentlyContinue) {
        Write-Host "✅ Jenkins already installed" -ForegroundColor Green
        return
    }
    
    # Download and install Jenkins
    $jenkinsUrl = "https://get.jenkins.io/windows-stable/jenkins.msi"
    $jenkinsInstaller = "$env:TEMP\jenkins.msi"
    
    Write-Host "📥 Downloading Jenkins..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $jenkinsUrl -OutFile $jenkinsInstaller
    
    Write-Host "🔧 Installing Jenkins..." -ForegroundColor Yellow
    Start-Process msiexec.exe -ArgumentList "/i", $jenkinsInstaller, "/quiet", "/norestart" -Wait
    
    Remove-Item $jenkinsInstaller
    
    # Start Jenkins service
    Write-Host "🚀 Starting Jenkins service..." -ForegroundColor Yellow
    Start-Service -Name Jenkins
    
    Write-Host "✅ Jenkins installed and started successfully" -ForegroundColor Green
    Write-Host "🌐 Access Jenkins at: http://localhost:8080" -ForegroundColor Cyan
    
    # Get initial admin password
    $passwordFile = "C:\Program Files\Jenkins\secrets\initialAdminPassword"
    if (Test-Path $passwordFile) {
        $initialPassword = Get-Content $passwordFile
        Write-Host "🔑 Initial admin password: $initialPassword" -ForegroundColor Cyan
    }
}

# Function to install Python
function Install-Python {
    Write-Host "🐍 Installing Python..." -ForegroundColor Yellow
    
    if (Get-Command python -ErrorAction SilentlyContinue) {
        Write-Host "✅ Python already installed" -ForegroundColor Green
        return
    }
    
    choco install python -y
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    # Install required Python packages
    Write-Host "📦 Installing Python dependencies..." -ForegroundColor Yellow
    python -m pip install --upgrade pip
    pip install jinja2 lxml beautifulsoup4 requests python-dateutil pyyaml pandas matplotlib seaborn plotly
    
    Write-Host "✅ Python and dependencies installed successfully" -ForegroundColor Green
}

# Function to install additional tools
function Install-AdditionalTools {
    Write-Host "🛠️ Installing additional tools..." -ForegroundColor Yellow
    
    # Install Visual Studio Code
    if (-not (Get-Command code -ErrorAction SilentlyContinue)) {
        choco install vscode -y
    }
    
    # Install Windows Terminal
    if (-not (Get-Command wt -ErrorAction SilentlyContinue)) {
        choco install microsoft-windows-terminal -y
    }
    
    Write-Host "✅ Additional tools installed" -ForegroundColor Green
}

# Function to create project structure
function Setup-ProjectStructure {
    Write-Host "📁 Setting up project structure..." -ForegroundColor Yellow
    
    $projectRoot = Get-Location
    
    # Create necessary directories
    $directories = @(
        "reports\templates",
        "config\trivy",
        "config\zap", 
        "config\dependency-check",
        "jenkins\scripts",
        "scripts"
    )
    
    foreach ($dir in $directories) {
        $fullPath = Join-Path $projectRoot $dir
        if (-not (Test-Path $fullPath)) {
            New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            Write-Host "📂 Created directory: $dir" -ForegroundColor Gray
        }
    }
    
    Write-Host "✅ Project structure created" -ForegroundColor Green
}

# Function to configure Docker
function Configure-Docker {
    Write-Host "🔧 Configuring Docker..." -ForegroundColor Yellow
    
    # Wait for Docker to be available
    $maxAttempts = 30
    $attempt = 0
    
    do {
        $attempt++
        try {
            docker version | Out-Null
            Write-Host "✅ Docker is running" -ForegroundColor Green
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                Write-Host "❌ Docker is not running. Please start Docker Desktop manually." -ForegroundColor Red
                return
            }
            Write-Host "⏳ Waiting for Docker to start... ($attempt/$maxAttempts)" -ForegroundColor Yellow
            Start-Sleep 5
        }
    } while ($attempt -lt $maxAttempts)
    
    # Pull required images
    Write-Host "📥 Pulling required Docker images..." -ForegroundColor Yellow
    $images = @(
        "jenkins/jenkins:lts",
        "portainer/portainer-ce:latest",
        "bkimminich/juice-shop:latest",
        "aquasec/trivy:latest",
        "anchore/syft:latest",
        "owasp/zap2docker-stable:latest",
        "instrumenta/nmap:latest",
        "owasp/dependency-check:latest"
    )
    
    foreach ($image in $images) {
        Write-Host "🐳 Pulling $image..." -ForegroundColor Gray
        docker pull $image
    }
    
    Write-Host "✅ Docker images pulled successfully" -ForegroundColor Green
}

# Function to validate installation
function Test-Installation {
    Write-Host "🔍 Validating installation..." -ForegroundColor Yellow
    
    $errors = @()
    
    # Test Git
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $errors += "Git not found"
    }
    
    # Test Docker
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        $errors += "Docker not found"
    } else {
        try {
            docker version | Out-Null
        } catch {
            $errors += "Docker not running"
        }
    }
    
    # Test Java
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        $errors += "Java not found"
    }
    
    # Test Python
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        $errors += "Python not found"
    }
    
    if ($errors.Count -eq 0) {
        Write-Host "✅ All components installed successfully!" -ForegroundColor Green
        return $true
    } else {
        Write-Host "❌ Installation issues found:" -ForegroundColor Red
        foreach ($error in $errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
        return $false
    }
}

# Function to display next steps
function Show-NextSteps {
    Write-Host "`n🎯 Setup Complete! Next Steps:" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green
    Write-Host "1. Ensure Docker Desktop is running" -ForegroundColor Cyan
    Write-Host "2. Start services: docker-compose up -d" -ForegroundColor Cyan
    Write-Host "3. Access Jenkins: http://localhost:8080" -ForegroundColor Cyan
    Write-Host "4. Access Portainer: http://localhost:9000" -ForegroundColor Cyan
    Write-Host "5. Configure Jenkins pipeline with this repository" -ForegroundColor Cyan
    Write-Host "`n📚 Documentation:" -ForegroundColor Yellow
    Write-Host "- README.md for detailed setup instructions" -ForegroundColor Gray
    Write-Host "- Check jenkins/Jenkinsfile for pipeline configuration" -ForegroundColor Gray
    Write-Host "`n🔧 Troubleshooting:" -ForegroundColor Yellow
    Write-Host "- Run: .\scripts\install-dependencies.ps1 to reinstall components" -ForegroundColor Gray
    Write-Host "- Check Docker Desktop is using WSL 2 backend" -ForegroundColor Gray
    Write-Host "- Ensure Windows features (WSL, Hyper-V) are enabled" -ForegroundColor Gray
}

# Main execution
function Main {
    if (-not (Test-Administrator)) {
        Write-Host "❌ This script must be run as Administrator" -ForegroundColor Red
        Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        exit 1
    }
    
    try {
        Install-Chocolatey
        Install-Git
        Install-Java
        Install-Python
        Install-Docker
        Install-Jenkins
        Install-AdditionalTools
        Setup-ProjectStructure
        
        if (-not $SkipDocker) {
            Configure-Docker
        }
        
        $installationValid = Test-Installation
        
        if ($installationValid) {
            Show-NextSteps
        } else {
            Write-Host "`n⚠️ Some components may need manual attention." -ForegroundColor Yellow
            Write-Host "Please check the error messages above and retry if needed." -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "❌ Setup failed with error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please check the error and run the script again." -ForegroundColor Yellow
        exit 1
    }
}

# Script entry point
Main
