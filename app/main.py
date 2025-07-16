import sys
import os
import logging
from flask import Flask, request, jsonify
from typing import Dict, Any

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.agents.security_agent import SecurityAgent
from config.config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize security agent
security_agent = SecurityAgent()
logger.info("Security agent initialized successfully")

@app.route('/analysis_agent', methods=['POST'])
def analysis_agent():
    """
    Main API endpoint for security analysis
    Expected input: {"query": "object to analyze"}
    Returns: {"analysis": "detailed analysis", "result": "ABNORMAL|CLEAN|UNKNOWN"}
    """
    try:
        # Log request details for debugging
        logger.info(f"Received request - Content-Type: {request.content_type}")
        logger.info(f"Request data: {request.get_data()}")
        
        # Get JSON data with fallback
        data = None
        try:
            data = request.get_json(force=True)
        except Exception as json_error:
            logger.error(f"JSON parsing error: {str(json_error)}")
            return jsonify({
                "analysis": f"Invalid JSON format: {str(json_error)}",
                "result": "UNKNOWN"
            }), 400
        
        # Validate data exists
        if not data:
            return jsonify({
                "analysis": "Empty request body. Expected JSON with 'query' field.",
                "result": "UNKNOWN"
            }), 400
        
        # Validate query parameter
        if 'query' not in data:
            return jsonify({
                "analysis": "Missing 'query' parameter in request.",
                "result": "UNKNOWN"
            }), 400
        
        query = data['query']
        if not query or not isinstance(query, str) or query.strip() == "":
            return jsonify({
                "analysis": "Invalid query. Query must be a non-empty string.",
                "result": "UNKNOWN"
            }), 400
        
        query = query.strip()
        logger.info(f"Received analysis request for: {query[:50]}...")
        
        # Perform analysis
        result = perform_analysis(query)
        
        # Log the result
        print(result)
        
        logger.info(f"Analysis completed with result: {result['result']}")
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            "analysis": f"Internal server error: {str(e)}",
            "result": "UNKNOWN"
        }), 500

def perform_analysis(query: str) -> Dict[str, Any]:
    """
    Perform security analysis using the main security agent
    """
    result = security_agent.analyze(query)
    logger.info("Analysis completed successfully")
    return result

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    openai_status = hasattr(security_agent, 'client') and security_agent.client is not None
    
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "agents": {
            "security_agent": True,
            "openai_client": openai_status
        },
        "capabilities": {
            "ai_analysis": openai_status,
            "multi_tool_analysis": True,
            "virustotal": True,
            "alienvault": True,
            "google_search": True
        }
    }), 200

@app.route('/', methods=['GET'])
def index():
    """Root endpoint with API information"""
    return jsonify({
        "name": "Security AI Agent",
        "version": "1.0.0",
        "description": "AI-powered security analysis agent",
        "endpoints": {
            "analysis": {
                "url": "/analysis_agent",
                "method": "POST",
                "description": "Analyze security objects (URLs, file paths, hashes, IPs)",
                "input": {"query": "object to analyze"},
                "output": {"analysis": "detailed analysis", "result": "ABNORMAL|CLEAN|UNKNOWN"}
            },
            "health": {
                "url": "/health",
                "method": "GET",
                "description": "Health check endpoint"
            }
        }
    }), 200

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "analysis": "Endpoint not found. Use POST /analysis_agent for security analysis.",
        "result": "UNKNOWN"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        "analysis": "Internal server error occurred.",
        "result": "UNKNOWN"
    }), 500

if __name__ == '__main__':
    try:
        logger.info("Starting Security AI Agent...")
        logger.info(f"Configuration: Host={Config.FLASK_HOST}, Port={Config.FLASK_PORT}, Debug={Config.FLASK_DEBUG}")
        
        # Start Flask application
        app.run(
            host=Config.FLASK_HOST,
            port=Config.FLASK_PORT,
            debug=Config.FLASK_DEBUG
        )
        
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1) 