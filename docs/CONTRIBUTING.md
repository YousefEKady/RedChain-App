# Contributing to Red Team Automation Framework

Thank you for your interest in contributing to the Red Team Automation Framework! This guide will help you understand the project structure, development workflow, and contribution guidelines.

## 📋 Table of Contents

- [Project Structure](#project-structure)
- [Development Setup](#development-setup)
- [File Structure Explanation](#file-structure-explanation)
- [Development Guidelines](#development-guidelines)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Security Considerations](#security-considerations)

## 🏗️ Project Structure

```
redteam_automation/
├── agents/                 # AI agents and security analysis
├── api/                   # API endpoint definitions
├── data/                  # Database and vector store data
├── database/              # Database models and migrations
├── docs/                  # Project documentation
├── output/                # Generated reports and engagement data
├── rag/                   # RAG (Retrieval Augmented Generation) components
├── reporting/             # Report generation and templates
├── services/              # Background services and schedulers
├── tests/                 # Test suite
├── tools/                 # Security tool integrations
├── utils/                 # Utility functions and helpers
├── web/                   # React frontend application
├── workflows/             # Engagement orchestration
├── config.py              # Application configuration
├── schemas.py             # Pydantic data models
├── simple_api.py          # Main FastAPI application
└── requirements.txt       # Python dependencies
```

## 🛠️ Development Setup

### Prerequisites
- Python 3.8+
- Node.js 18+
- Git
- Google AI API Key

### Local Development

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YousefEKady/RedChain-App.git
   cd redteam_automation
   ```

2. **Backend Setup**
   ```bash
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Copy environment file
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Frontend Setup**
   ```bash
   cd web
   npm install
   ```

4. **Start Development Servers**
   ```bash
   # Terminal 1: Backend
   uvicorn simple_api:app --host 0.0.0.0 --port 8000 --reload
   
   # Terminal 2: Frontend
   cd web
   npm run dev
   ```

## 📁 File Structure Explanation

### Core Application Files

#### `simple_api.py`
**Purpose**: Main FastAPI application server
- Defines all REST API endpoints
- Handles CORS middleware configuration
- Manages application startup/shutdown events
- Integrates with all backend services

**Key Responsibilities**:
- API route definitions
- Request/response handling
- Background task management
- Static file serving

#### `config.py`
**Purpose**: Centralized configuration management
- Uses Pydantic Settings for type-safe configuration
- Loads environment variables from `.env` file
- Provides validation for configuration values
- Defines default values and constraints

**Key Features**:
- API key management
- Tool path configuration
- Rate limiting settings
- Database paths
- Model parameters

#### `schemas.py`
**Purpose**: Pydantic data models and validation
- Defines all data structures used throughout the application
- Provides input validation and serialization
- Ensures type safety across the codebase

**Key Models**:
- `Finding`: Security vulnerability representation
- `Scope`: Engagement scope definition
- `BurpIssue`: Burp Suite issue parsing
- `EngagementConfig`: Engagement configuration

### Directory Breakdown

#### `agents/`
**Purpose**: AI-powered security analysis agents

- **`security_agent.py`**: Main AI agent for security analysis
  - Integrates with Google Gemini AI
  - Analyzes findings and generates insights
  - Provides remediation recommendations

#### `api/`
**Purpose**: API endpoint organization

- **`endpoints.py`**: Additional API route definitions
  - Modular endpoint organization
  - Specialized route handlers

#### `database/`
**Purpose**: Database management and models

- **`database.py`**: Database connection and table definitions
  - SQLite database setup
  - Table schema definitions
  - Database initialization

- **`models.py`**: SQLAlchemy ORM models
  - Database entity definitions
  - Relationship mappings

- **`migrations/`**: Database schema migrations
  - Version-controlled schema changes
  - Migration scripts for database updates

#### `rag/`
**Purpose**: Retrieval Augmented Generation components

- **`knowledge_base.py`**: Knowledge management system
  - Stores security techniques and methodologies
  - Provides similarity search capabilities
  - Integrates with vector database

- **`vector_store.py`**: Vector database operations
  - ChromaDB integration
  - Embedding generation and storage
  - Similarity search implementation

#### `reporting/`
**Purpose**: Report generation system

- **`generator.py`**: Report generation engine
  - Multi-format report generation
  - Template processing
  - AI-enhanced report content

- **`templates/`**: Report templates
  - Jinja2 templates for different report formats
  - Styling and layout definitions

#### `services/`
**Purpose**: Background services and schedulers

- **`report_scheduler.py`**: Automated report generation
  - Scheduled report generation
  - Background task management
  - Engagement monitoring

- **`notification_service.py`**: Notification system
  - Webhook notifications
  - Email alerts (if configured)
  - Status updates

#### `tools/`
**Purpose**: Security tool integrations

- **`burp_parser.py`**: Burp Suite XML parser
  - Parses Burp Suite export files
  - Extracts security findings
  - Converts to internal data format

- **`project_discovery.py`**: Project Discovery tool integration
  - Subfinder, HTTPX, Nuclei integration
  - Tool execution and output parsing
  - Result processing and analysis

#### `utils/`
**Purpose**: Utility functions and helpers

- **`logging.py`**: Logging configuration
  - Structured logging setup
  - Log formatting and handlers

- **`safety_checks.py`**: Security validation
  - Scope validation
  - Target verification
  - Safety constraint enforcement

- **`scope_validator.py`**: Scope management
  - YAML scope parsing
  - Target validation
  - Scope compliance checking

#### `workflows/`
**Purpose**: Engagement orchestration

- **`orchestrator.py`**: Main workflow orchestrator
  - Coordinates engagement phases
  - Manages tool execution
  - Handles workflow state

#### `web/`
**Purpose**: React frontend application

- **Modern React 19 application with TypeScript**
- **Tailwind CSS for styling**
- **React Router for navigation**
- **Axios for API communication**

**Key Components**:
- Dashboard for engagement monitoring
- Scope management interface
- Report generation and viewing
- Real-time status updates

#### `tests/`
**Purpose**: Test suite

- **`conftest.py`**: Pytest configuration and fixtures
- **`test_*.py`**: Individual test modules
  - Unit tests for core functionality
  - Integration tests for API endpoints
  - End-to-end workflow tests

## 🔧 Development Guidelines

### Code Organization

1. **Separation of Concerns**
   - Keep business logic separate from API handlers
   - Use services for complex operations
   - Maintain clear module boundaries

2. **Error Handling**
   - Use appropriate HTTP status codes
   - Provide meaningful error messages
   - Log errors with sufficient context

3. **Configuration Management**
   - Use environment variables for configuration
   - Provide sensible defaults
   - Validate configuration on startup

### Adding New Features

1. **API Endpoints**
   ```python
   # In simple_api.py or api/endpoints.py
   @app.post("/api/v1/new-feature")
   async def new_feature_endpoint(request: NewFeatureRequest):
       try:
           result = await process_new_feature(request)
           return {"status": "success", "data": result}
       except Exception as e:
           logger.error(f"New feature error: {e}")
           raise HTTPException(status_code=500, detail=str(e))
   ```

2. **Data Models**
   ```python
   # In schemas.py
   class NewFeatureRequest(BaseModel):
       name: str = Field(..., description="Feature name")
       options: Dict[str, Any] = Field(default_factory=dict)
       
       @validator('name')
       def validate_name(cls, v):
           if not v.strip():
               raise ValueError("Name cannot be empty")
           return v.strip()
   ```

3. **Services**
   ```python
   # In services/new_service.py
   class NewService:
       def __init__(self, config: Settings):
           self.config = config
           
       async def process_request(self, request: NewFeatureRequest):
           # Implementation here
           pass
   ```

### Database Changes

1. **Schema Updates**
   - Create migration files in `database/migrations/`
   - Update `database.py` with new table definitions
   - Test migrations thoroughly

2. **Model Updates**
   - Update Pydantic schemas in `schemas.py`
   - Ensure backward compatibility
   - Add appropriate validation

### Frontend Development

1. **Component Structure**
   ```typescript
   // In web/app/components/
   interface NewComponentProps {
     data: SomeDataType;
     onAction: (id: string) => void;
   }
   
   export function NewComponent({ data, onAction }: NewComponentProps) {
     // Component implementation
   }
   ```

2. **API Integration**
   ```typescript
   // In web/app/services/
   export async function callNewAPI(request: NewFeatureRequest) {
     const response = await axios.post('/api/v1/new-feature', request);
     return response.data;
   }
   ```

## 🧪 Testing

### Running Tests

```bash
# Backend tests
pytest tests/ -v

# Frontend tests
cd web
npm test

# Coverage report
pytest tests/ --cov=. --cov-report=html
```

### Writing Tests

1. **Unit Tests**
   ```python
   # tests/test_new_feature.py
   import pytest
   from your_module import new_function
   
   def test_new_function():
       result = new_function("test_input")
       assert result == "expected_output"
   ```

2. **API Tests**
   ```python
   # tests/test_api.py
   def test_new_endpoint(client):
       response = client.post("/api/v1/new-feature", json={"name": "test"})
       assert response.status_code == 200
       assert response.json()["status"] == "success"
   ```

## 🎨 Code Style

### Python
- Follow PEP 8 style guidelines
- Use type hints for all function parameters and return values
- Use meaningful variable and function names

### TypeScript/React
- Use TypeScript for all new code
- Follow React best practices
- Use functional components with hooks
- Implement proper error boundaries

### Documentation
- Document all public functions and classes
- Use docstrings for Python code
- Add JSDoc comments for TypeScript functions
- Keep README and API documentation up to date

## 📝 Submitting Changes

### Pull Request Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Follow coding standards
   - Add tests for new functionality
   - Update documentation

3. **Test Changes**
   ```bash
   # Run all tests
   pytest tests/
   cd web && npm test
   
   # Check code style
   flake8 .
   black --check .
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

Use conventional commits format:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes
- `refactor:` - Code refactoring
- `test:` - Test additions or changes
- `chore:` - Maintenance tasks

### PR Requirements

- [ ] All tests pass
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] Changes are backward compatible
- [ ] Security implications are considered

## 🔒 Security Considerations

### Security Guidelines

1. **Input Validation**
   - Validate all user inputs
   - Use Pydantic models for request validation
   - Sanitize file uploads

2. **Authentication & Authorization**
   - Implement proper authentication for production
   - Use role-based access control
   - Validate user permissions

3. **Data Protection**
   - Never log sensitive information
   - Use environment variables for secrets
   - Implement proper error handling

4. **Tool Safety**
   - Validate scope before tool execution
   - Implement rate limiting
   - Add safety checks for destructive operations

### Reporting Security Issues

If you discover a security vulnerability, please:
1. **DO NOT** create a public issue
2. Email the maintainers directly
3. Provide detailed information about the vulnerability
4. Allow time for the issue to be addressed before disclosure

## 🤝 Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn and grow
- Focus on the technical aspects

### Getting Help

- Check existing documentation
- Search through existing issues
- Ask questions in discussions
- Provide detailed information when reporting issues

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [ChromaDB Documentation](https://docs.trychroma.com/)
- [Google AI Documentation](https://ai.google.dev/)

---

**Thank you for contributing to the Red Team Automation Framework!** 🚀

Your contributions help make security testing more efficient and accessible for the entire community.