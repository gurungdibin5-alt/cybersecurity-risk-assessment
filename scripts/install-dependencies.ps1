# Install Dependencies Script for Windows 11
# Run as Administrator

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "📦 Installing/Updating Dependencies..." -ForegroundColor Green

# Function to install or update Python packages
function Install-PythonDependencies {
    Write-Host "🐍 Installing Python dependencies..." -ForegroundColor Yellow
    
    $packages = @(
        "jinja2>=3.1.2",
        "lxml>=4.9.1", 
        "beautifulsoup4>=4.11.1",
        "requests>=2.28.1",
        "python-dateutil>=2.8.2",
        "pyyaml>=6.0",
        "pandas>=1.5.0",
        "matplotlib>=3.6.0",
        "seaborn>=0.12.0",
        "plotly>=5.11.0"
    )
    
    # Update pip first
    python -m pip install --upgrade pip
    
    foreach ($package in $packages) {
        Write-Host "Installing $package..." -ForegroundColor Gray
        pip install $package --upgrade
    }
    
    Write-Host "✅ Python dependencies installed" -ForegroundColor Green
}

# Function to install Jenkins plugins
function Install-JenkinsPlugins {
    Write-Host "🏗️ Installing Jenkins plugins..." -ForegroundColor Yellow
    
    $pluginList = @(
        "docker-workflow",
        "docker-pipeline", 
        "pipeline-stage-view",
        "htmlpublisher",
        "git",
        "workflow-aggregator",
        "blueocean",
        "build-timeout",
        "credentials-binding",
        "timestamper",
        "ws-cleanup",
        "ant",
        "gradle"
    )
    
    # Jenkins CLI jar download
    $jenkinsUrl = "http://localhost:8080"
    $cliJar = "$env:TEMP\jenkins-cli.jar"
    
    try {
        Write-Host "📥 Downloading Jenkins CLI..." -ForegroundColor Gray
        Invoke-WebRequest -Uri "$jenkinsUrl/jnlpJars/jenkins-cli.jar" -OutFile $cliJar
        
        foreach ($plugin in $pluginList) {
            Write-Host "Installing plugin: $plugin..." -ForegroundColor Gray
            java -jar $cliJar -s $jenkinsUrl install-plugin $plugin
        }
        
        Write-Host "🔄 Restarting Jenkins..." -ForegroundColor Gray
        java -jar $cliJar -s $jenkinsUrl restart
        
    } catch {
        Write-Host "⚠️ Could not install Jenkins plugins automatically." -ForegroundColor Yellow
        Write-Host "Please install them manually via Jenkins web interface." -ForegroundColor Yellow
    } finally {
        if (Test-Path $cliJar) {
            Remove-Item $cliJar
        }
    }
}

# Function to update Docker images
function Update-DockerImages {
    Write-Host "🐳 Updating Docker images..." -ForegroundColor Yellow
    
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
        Write-Host "📥 Pulling $image..." -ForegroundColor Gray
        docker pull $image
    }
    
    Write-Host "✅ Docker images updated" -ForegroundColor Green
}

# Function to clean up old Docker resources
function Cleanup-Docker {
    Write-Host "🧹 Cleaning up Docker resources..." -ForegroundColor Yellow
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes
    docker volume prune -f
    
    # Remove unused networks
    docker network prune -f
    
    Write-Host "✅ Docker cleanup completed" -ForegroundColor Green
}

# Main execution
try {
    Install-PythonDependencies
    
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Update-DockerImages
        Cleanup-Docker
    } else {
        Write-Host "⚠️ Docker not found, skipping Docker-related updates" -ForegroundColor Yellow
    }
    
    # Only try Jenkins plugins if Jenkins is running
    if (Get-Service -Name Jenkins -ErrorAction SilentlyContinue) {
        if ((Get-Service -Name Jenkins).Status -eq 'Running') {
            Install-JenkinsPlugins
        } else {
            Write-Host "⚠️ Jenkins service not running, skipping plugin installation" -ForegroundColor Yellow
        }
    }
    
    Write-Host "✅ Dependencies updated successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "❌ Error updating dependencies: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
