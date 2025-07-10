# 🛡️ AI Cybersecurity Fraud Detection System

A comprehensive AI-driven cybersecurity tool that detects fraudulent activities by analyzing user-uploaded files. The system integrates with multiple threat intelligence APIs and provides educational workshops for cybersecurity awareness.

## ✨ Features

### 🔍 Advanced File Analysis
- **Multi-format Support**: PDF, DOCX, ZIP, executables, images, and more
- **Hash-based Detection**: SHA256 file fingerprinting and deduplication
- **Content Analysis**: Text extraction, metadata parsing, and string analysis
- **Behavioral Analysis**: Suspicious pattern detection and anomaly identification

### 🤖 AI-Powered Detection
- **Machine Learning Models**: Random Forest and Isolation Forest algorithms
- **Feature Engineering**: File entropy, string patterns, and metadata analysis
- **Adaptive Learning**: Continuous improvement through user feedback
- **Confidence Scoring**: Probabilistic threat assessment

### 🌐 Threat Intelligence Integration
- **VirusTotal API**: Global malware database lookup
- **MalwareBazaar**: Free threat intelligence service
- **Hybrid Analysis**: Advanced dynamic analysis (optional)
- **Real-time Updates**: Latest threat indicators

### 📚 Educational Workshop
- **Interactive Modules**: Malware basics, phishing awareness, secure file handling
- **Progress Tracking**: User learning analytics and completion certificates
- **Practical Exercises**: Hands-on cybersecurity training
- **Assessment System**: Knowledge verification through quizzes

### 📊 Comprehensive Reporting
- **Detailed Analysis Reports**: PDF and JSON format exports
- **Executive Summaries**: High-level threat assessments
- **Actionable Recommendations**: Step-by-step remediation guidance
- **Historical Analytics**: Trend analysis and system metrics

### 🔒 Security & Compliance
- **Secure File Handling**: Isolated processing environment
- **Data Privacy**: GDPR and CCPA compliance considerations
- **Access Controls**: Rate limiting and authentication
- **Audit Logging**: Complete activity tracking

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- 4GB+ RAM recommended
- 2GB+ disk space for models and uploads

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd cybersecurity-fraud-detection
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Initialize the database**
```bash
python -c "from app.database import engine; from app.models import Base; Base.metadata.create_all(bind=engine)"
```

5. **Start the application**
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

6. **Access the application**
- Web Interface: http://localhost:8000
- API Documentation: http://localhost:8000/api/docs
- Workshop: http://localhost:8000/api/workshop

## 📋 API Configuration

### Required Environment Variables
```env
# Minimal configuration
DATABASE_URL=sqlite:///./fraud_detection.db
SECRET_KEY=your-secure-secret-key
```

### Optional API Keys
```env
# Enhanced threat intelligence (free registration required)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key
```

### API Key Setup

#### VirusTotal (Recommended)
1. Visit https://www.virustotal.com/gui/join-us
2. Register for a free account
3. Navigate to your profile and copy the API key
4. Add to `.env` file: `VIRUSTOTAL_API_KEY=your_key_here`

#### Hybrid Analysis (Optional)
1. Visit https://www.hybrid-analysis.com/
2. Register for a free account
3. Generate an API key in your profile
4. Add to `.env` file: `HYBRID_ANALYSIS_API_KEY=your_key_here`

## 🔧 Usage Examples

### File Upload and Analysis
```bash
# Upload a file for analysis
curl -X POST "http://localhost:8000/api/analysis/upload" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@suspicious_file.pdf"

# Check analysis status
curl "http://localhost:8000/api/analysis/status/1"

# Download PDF report
curl "http://localhost:8000/api/reports/analysis/1/pdf" -o report.pdf
```

### Workshop Progress
```bash
# Get available modules
curl "http://localhost:8000/api/workshop/modules"

# Submit quiz answers
curl -X POST "http://localhost:8000/api/workshop/modules/malware_basics/quiz" \
  -H "Content-Type: application/json" \
  -d '{"answers": [1, 2], "user_session": "user123"}'
```

### Feedback Submission
```bash
# Submit feedback on analysis
curl -X POST "http://localhost:8000/api/feedback/submit" \
  -H "Content-Type: application/json" \
  -d '{
    "analysis_id": 1,
    "feedback_type": "FALSE_POSITIVE",
    "user_comment": "This file is actually safe"
  }'
```

## 🏗️ Architecture

### Backend Components
- **FastAPI**: High-performance web framework
- **SQLAlchemy**: Database ORM with SQLite/PostgreSQL support
- **Scikit-learn**: Machine learning algorithms
- **AsyncIO**: Asynchronous processing for scalability

### File Processing Pipeline
1. **Upload Validation**: File type and size verification
2. **Hash Calculation**: SHA256 fingerprinting and deduplication
3. **Metadata Extraction**: File-specific parsing and analysis
4. **API Integration**: Parallel threat intelligence queries
5. **ML Analysis**: Feature extraction and prediction
6. **Result Aggregation**: Combined threat assessment
7. **Report Generation**: Detailed findings and recommendations

### Security Measures
- **Input Validation**: Comprehensive file and parameter checking
- **Sandboxed Execution**: Isolated file processing environment
- **Rate Limiting**: API abuse prevention
- **Secure File Storage**: Temporary file handling with cleanup
- **Audit Logging**: Complete activity tracking

## 📊 Supported File Types

### Documents
- PDF (.pdf) - Text extraction and metadata analysis
- Microsoft Word (.docx, .doc) - Content and macro detection
- Text files (.txt) - Content analysis

### Archives
- ZIP (.zip) - Content enumeration and analysis
- RAR (.rar) - Archive inspection
- 7-Zip (.7z) - Compressed file analysis

### Executables
- Windows PE (.exe, .dll, .msi) - Static analysis
- Scripts (.bat, .cmd, .ps1) - Content inspection
- System files (.scr, .pif, .com) - Signature analysis

### Images
- JPEG (.jpg, .jpeg) - EXIF data extraction
- PNG (.png) - Metadata analysis
- GIF (.gif) - Animation and metadata inspection

### Web Content
- HTML (.html, .htm) - Script and link analysis
- JavaScript (.js) - Code pattern detection
- CSS (.css) - Style sheet inspection

## 🧠 Machine Learning Models

### Isolation Forest
- **Purpose**: Anomaly detection in file characteristics
- **Features**: File entropy, size, string patterns
- **Output**: Anomaly score and classification

### Random Forest Classifier
- **Purpose**: Supervised malware classification
- **Features**: Combined numerical and text features
- **Output**: Probability scores and binary classification

### TF-IDF Vectorizer
- **Purpose**: Text feature extraction from file strings
- **Features**: N-gram analysis of extracted content
- **Output**: Vectorized text representations

### Feature Engineering
- File size (log-transformed)
- String count and entropy
- Suspicious indicator count
- Metadata characteristics
- Content-based features

## 📈 Monitoring and Analytics

### System Metrics
- Analysis throughput and response times
- API success rates and error tracking
- Model performance and accuracy metrics
- User engagement and workshop completion

### Threat Intelligence
- Detection rate trends over time
- False positive/negative analysis
- Emerging threat pattern identification
- API coverage and reliability

## 🔧 Development

### Project Structure
```
├── app/
│   ├── main.py              # FastAPI application
│   ├── models.py            # Database models
│   ├── schemas.py           # Pydantic schemas
│   ├── database.py          # Database configuration
│   ├── core/
│   │   └── config.py        # Application settings
│   ├── routers/             # API endpoints
│   │   ├── analysis.py      # File analysis routes
│   │   ├── workshop.py      # Educational modules
│   │   ├── feedback.py      # User feedback
│   │   └── reports.py       # Report generation
│   └── services/            # Business logic
│       ├── file_processor.py    # File analysis
│       ├── api_integrator.py    # External APIs
│       ├── ml_detector.py       # ML models
│       └── report_generator.py  # PDF reports
├── models/                  # ML model storage
├── uploads/                 # Temporary file storage
├── requirements.txt         # Python dependencies
├── .env.example            # Configuration template
└── README.md               # This file
```

### Running Tests
```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest tests/

# Run with coverage
pytest --cov=app tests/
```

### Adding New Features

#### New File Type Support
1. Add extension to `settings.allowed_extensions`
2. Implement processor in `FileProcessor._process_*` method
3. Update feature extraction in `MLFraudDetector`
4. Add documentation and tests

#### New API Integration
1. Create method in `APIIntegrator`
2. Add API configuration to settings
3. Update result aggregation logic
4. Document API key requirements

#### New ML Model
1. Implement in `MLFraudDetector`
2. Add model persistence logic
3. Update feature extraction pipeline
4. Validate on test dataset

## 🔒 Security Considerations

### File Processing
- All files processed in isolated environment
- Temporary files automatically cleaned up
- No execution of uploaded content
- Size and type restrictions enforced

### API Security
- Rate limiting on all endpoints
- Input validation and sanitization
- Secure error handling without information leakage
- Optional authentication for sensitive operations

### Data Privacy
- File hashes used for deduplication only
- No persistent storage of file content
- User feedback anonymized
- Compliance with data protection regulations

### Infrastructure Security
- Environment variable configuration
- Database connection security
- HTTPS recommended for production
- Regular security updates required

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Update documentation
5. Submit a pull request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/cybersecurity-fraud-detection.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio black flake8

# Run pre-commit checks
black app/
flake8 app/
pytest
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Documentation
- API Documentation: `/api/docs` endpoint
- Interactive Workshop: `/api/workshop` endpoint
- System Health: `/health` endpoint

### Common Issues

#### "API key not configured"
- Add API keys to `.env` file
- Restart the application
- System works without API keys but with reduced functionality

#### "Model initialization failed"
- Ensure sufficient disk space (2GB+)
- Check Python version compatibility
- Restart application to rebuild models

#### "File upload too large"
- Check `MAX_FILE_SIZE` setting
- Default limit is 100MB
- Increase server memory for larger limits

### Getting Help
- Check the API documentation at `/api/docs`
- Review logs for detailed error messages
- Create an issue for bugs or feature requests
- Consult the workshop modules for cybersecurity guidance

## 🔄 Changelog

### Version 1.0.0
- Initial release with core functionality
- Multi-format file analysis
- ML-based fraud detection
- Threat intelligence integration
- Educational workshop modules
- Comprehensive reporting system

## 🎯 Roadmap

### Short Term
- [ ] React frontend for enhanced UI
- [ ] Additional file format support
- [ ] Enhanced ML model accuracy
- [ ] Real-time analysis dashboard

### Medium Term
- [ ] Kubernetes deployment support
- [ ] Advanced behavioral analysis
- [ ] Integration with SIEM systems
- [ ] Mobile application

### Long Term
- [ ] Federated learning capabilities
- [ ] Advanced threat hunting features
- [ ] AI-powered incident response
- [ ] Global threat intelligence sharing

---

**Built with ❤️ for cybersecurity professionals and enthusiasts worldwide.**