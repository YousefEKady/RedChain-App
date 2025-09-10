# Red Team Automation Framework

A comprehensive automated red team engagement platform that combines AI-powered security analysis with modern tooling for efficient penetration testing and vulnerability assessment.

## 🚀 Features

### Core Capabilities
- **Automated Engagement Management**: Create, track, and manage red team engagements with comprehensive reporting
- **AI-Powered Analysis**: Leverage Google's Gemini AI for intelligent vulnerability analysis and insights
- **Multi-Tool Integration**: Seamlessly integrate with industry-standard tools (Subfinder, HTTPX, Nuclei, Burp Suite)
- **Real-time Dashboard**: Modern React-based web interface for monitoring and controlling engagements
- **Automated Reporting**: Generate professional reports in multiple formats.
- **Knowledge Base**: RAG-powered knowledge management for security techniques and methodologies

### Advanced Features
- **Burp Suite Integration**: Parse and analyze Burp Suite logs with AI-enhanced findings
- **Scheduled Reporting**: Automated report generation with configurable schedules
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming target systems
- **Safety Checks**: Comprehensive safety validations to prevent unauthorized testing

## 🏗️ Architecture

### Backend (Python/FastAPI)
- **API Server**: RESTful API built with FastAPI for high performance
- **AI Integration**: Google Generative AI (Gemini) for security analysis
- **Vector Database**: ChromaDB for knowledge base and similarity search
- **Task Scheduling**: Background task management for long-running engagements
- **Database**: SQLite for engagement and report data persistence

### Frontend (React/TypeScript)
- **Modern UI**: React 19 with TypeScript and Tailwind CSS
- **Real-time Updates**: Live engagement monitoring and status updates
- **Responsive Design**: Mobile-friendly interface with modern UX patterns
- **Component Library**: Headless UI components for accessibility

## 📋 Prerequisites

- Python 3.8+
- Node.js 18+
- Google AI API Key (for Gemini integration)
- Optional: Project Discovery tools (Subfinder, HTTPX, Nuclei)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git https://github.com/YousefEKady/RedChain-App.git
cd redteam_automation
```

### 2. Backend Setup
```bash
# Install Python dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env

# Edit .env file with your configuration
# Required: GOOGLE_API_KEY
# Optional: Tool paths and API keys
```

### 3. Frontend Setup
```bash
cd web
npm install
```

### 4. Configuration

Edit the `.env` file with your settings:

```env
# Required
GOOGLE_API_KEY=your_google_api_key_here

# Optional Tool Paths
SUBFINDER_PATH=/path/to/subfinder
HTTPX_PATH=/path/to/httpx
NUCLEI_PATH=/path/to/nuclei
NUCLEI_TEMPLATES_PATH=/path/to/nuclei-templates

# Project Discovery (Optional)
PROJECTDISCOVERY_API_KEY=your_pd_api_key
PROJECTDISCOVERY_TEAM_ID=your_team_id

# Model Configuration
GEMINI_MODEL=gemini-2.0-flash
MODEL_TEMPERATURE=0.1
MAX_TOKENS=4096

# Rate Limiting
RATE_LIMIT_RPM=60
RATE_LIMIT_DELAY=1.0
```

## 🚀 Usage

### Starting the Application

#### Development Mode
```bash
# Terminal 1: Start backend
uvicorn simple_api:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Start frontend
cd web
npm run dev
```

#### Production Mode
```bash
# Build frontend
cd web
npm run build

# Start backend (serves both API and frontend)
uvicorn simple_api:app --host 0.0.0.0 --port 8000
```

### Access Points
- **Web Interface**: http://localhost:3000 (development) or http://localhost:8000 (production)
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 📖 Quick Start Guide

### 1. Create an Engagement
1. Access the web interface
2. Navigate to "New Engagement"
3. define your scope
4. Configure engagement settings
5. Start the engagement

### 2. Upload Burp Suite Logs (Soon)
1. Go to "Burp Analysis"
2. Upload your Burp Suite XML export
3. Configure analysis options
4. Review AI-enhanced findings

### 3. Generate Reports
1. Navigate to completed engagements
2. Click "Generate Report"
3. Download the professional report

## 🔧 Configuration

### Tool Configuration
The framework supports various security tools:
- **Subfinder**: Subdomain enumeration
- **HTTPX**: HTTP probing and discovery
- **Nuclei**: Vulnerability scanning with templates
- **Burp Suite**: Manual testing integration

## 🔒 Security Considerations

- **Authorization Required**: Always ensure proper authorization before testing
- **Scope Validation**: Built-in scope checking to prevent out-of-scope testing
- **Rate Limiting**: Configurable rate limits to avoid service disruption
- **Safety Checks**: Multiple validation layers for target verification
- **Audit Logging**: Comprehensive logging of all activities

## 🤝 Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for detailed contribution guidelines.

## 📚 Documentation

- [API Documentation](docs/API-documentation.md)
- [Contributing Guide](docs/CONTRIBUTING.md)
- [Architecture Overview](docs/architecture.md)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before conducting any security assessments. The developers are not responsible for any misuse of this tool.

## 🆘 Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information

## 🙏 Acknowledgments

- Google Generative AI for powerful AI capabilities
- Project Discovery for excellent security tools
- The security community for continuous inspiration

---

**Built with ❤️ for the security community**