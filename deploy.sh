#!/bin/bash

# AI Cybersecurity Fraud Detection System - Quick Deploy
echo "🛡️  Deploying AI Cybersecurity Fraud Detection System..."

# Create directories
mkdir -p uploads models

# Start the server
echo "🚀 Starting server on http://localhost:8000"
python run_server.py