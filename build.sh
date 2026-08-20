#!/bin/bash
# Exit on error
set -o errexit

# Install Python dependencies
pip install -r requirements.txt

# Build the React frontend
cd ui
npm install
npm run build
cd ..
