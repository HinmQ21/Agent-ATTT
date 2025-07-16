# Security AI Agent

AI-powered security analysis agent for threat detection and assessment using multiple security tools and OpenAI GPT-4o mini.

## Features

- **Multi-tool Analysis**: Uses VirusTotal, AlienVault OTX, and Google Search for comprehensive threat intelligence
- **AI-Powered Classification**: OpenAI GPT-4o mini for intelligent analysis and decision making
- **Multiple Object Types**: Supports URLs, file paths, file hashes, and IP addresses
- **Fallback Mechanisms**: Backup analysis when external APIs are unavailable
- **Docker Support**: Easy deployment with Docker and Docker Compose
- **RESTful API**: Simple JSON API for integration

## Classification Results

- **CLEAN**: Object is safe and poses no security threat
- **ABNORMAL**: Object is malicious or suspicious and requires attention
- **UNKNOWN**: Insufficient information to make a definitive assessment

## Quick Start

### Using Docker (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd security-ai-agent
   ```

2. **Configure API Keys**
   Create a `.env` file with your API keys:
   ```bash
   # Required for AI analysis
   OPENAI_API_KEY=your_openai_api_key_here
   
   # Optional but recommended
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ALIENVAULT_API_KEY=your_alienvault_otx_api_key_here
   
   # Flask Configuration
   FLASK_HOST=0.0.0.0
   FLASK_PORT=8989
   FLASK_DEBUG=false
   ```

3. **Build and Run**
   ```bash
   docker-compose up --build
   ```

4. **Test the API**
   ```bash
   curl -X POST http://localhost:8989/analysis_agent \
     -H "Content-Type: application/json" \
     -d '{"query": "https://viettelstore.vn/"}'
   ```

### Manual Installation

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set Environment Variables**
   ```bash
   export OPENAI_API_KEY="your_key_here"
   export VIRUSTOTAL_API_KEY="your_key_here"
   export ALIENVAULT_API_KEY="your_key_here"
   ```

3. **Run the Application**
   ```bash
   python app/main.py
   ```

## API Usage

### Analyze Security Objects

**Endpoint**: `POST /analysis_agent`

**Request**:
```json
{
  "query": "object_to_analyze"
}
```

**Response**:
```json
{
  "analysis": "Detailed analysis explanation",
  "result": "CLEAN|ABNORMAL|UNKNOWN"
}
```

### Test Cases

```bash
# Test legitimate URL
curl -X POST http://localhost:8989/analysis_agent \
  -H "Content-Type: application/json" \
  -d '{"query": "https://viettelstore.vn/"}'

# Test suspicious file path
curl -X POST http://localhost:8989/analysis_agent \
  -H "Content-Type: application/json" \
  -d '{"query": "C:\\Windows\\NetworkDistribution\\svchost.exe"}'

# Test legitimate Windows process
curl -X POST http://localhost:8989/analysis_agent \
  -H "Content-Type: application/json" \
  -d '{"query": "C:\\windows\\SysWOW64\\schtasks.exe"}'

# Test malicious file hash
curl -X POST http://localhost:8989/analysis_agent \
  -H "Content-Type: application/json" \
  -d '{"query": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1"}'
```

### Health Check

```bash
curl http://localhost:8989/health
```

## API Keys Setup

### OpenAI API (Required)
1. Visit [OpenAI Platform](https://platform.openai.com/api-keys)
2. Create a new API key
3. Set `OPENAI_API_KEY` environment variable

### VirusTotal API (Optional)
1. Register at [VirusTotal](https://www.virustotal.com/gui/my-apikey)
2. Get your API key
3. Set `VIRUSTOTAL_API_KEY` environment variable

### AlienVault OTX API (Optional)
1. Register at [AlienVault OTX](https://otx.alienvault.com/api)
2. Get your API key
3. Set `ALIENVAULT_API_KEY` environment variable

## Architecture

```
security-ai-agent/
├── app/
│   ├── agents/           # AI analysis agents
│   │   ├── security_agent.py    # Main AI-powered agent
│   │   └── analyzer.py          # Backup heuristic analyzer
│   ├── tools/            # Security analysis tools
│   │   ├── virustotal.py        # VirusTotal integration
│   │   ├── alienvault.py        # AlienVault OTX integration
│   │   └── google_search.py     # Google Search patterns
│   ├── utils/            # Utility functions
│   │   └── helpers.py           # Object classification & validation
│   └── main.py           # Flask application
├── config/
│   └── config.py         # Configuration management
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
└── docker-compose.yml   # Docker Compose setup
```

## Development

### Running Tests
```bash
# Test individual components
python -m pytest tests/

# Test API endpoints
python test_api.py
```

### Adding New Security Tools
1. Create a new tool class in `app/tools/`
2. Implement the analysis interface
3. Add to `SecurityAgent` initialization
4. Update configuration as needed

## Deployment

### Production Deployment
```bash
# Build for production
docker build -t security-ai-agent:latest .

# Run with environment variables
docker run -d \
  -p 8989:8989 \
  -e OPENAI_API_KEY="your_key" \
  -e VIRUSTOTAL_API_KEY="your_key" \
  -e ALIENVAULT_API_KEY="your_key" \
  security-ai-agent:latest
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-ai-agent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: security-ai-agent
  template:
    metadata:
      labels:
        app: security-ai-agent
    spec:
      containers:
      - name: security-ai-agent
        image: security-ai-agent:latest
        ports:
        - containerPort: 8989
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: api-keys
              key: openai-key
```

## Troubleshooting

### Common Issues

1. **API Key Errors**
   - Verify your API keys are correctly set
   - Check API key permissions and quotas
   - The system will fallback to heuristic analysis if external APIs fail

2. **Docker Issues**
   - Ensure Docker and Docker Compose are installed
   - Check port 8989 is not in use
   - Verify .env file exists and is properly formatted

3. **Analysis Errors**
   - Check application logs for detailed error messages
   - Verify input format matches expected JSON structure
   - Ensure query parameter is a valid string

### Logs
```bash
# View application logs
docker-compose logs -f security-ai-agent

# Check health status
curl http://localhost:8989/health
```

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Support

For issues and questions, please open an issue on the GitHub repository. 