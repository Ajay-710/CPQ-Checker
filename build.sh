#!/bin/bash
# Exit on error
set -o errexit

# Install Python dependencies
python -m pip install --no-cache-dir -r requirements.txt
python -m playwright install chromium

# Build the React frontend
cd ui
npm ci
npm run build
cd ..
