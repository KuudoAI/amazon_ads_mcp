#!/bin/bash

# Setup script for Amazon Ads API MCP Server

echo "Setting up Amazon Ads API MCP Server..."

# Check if .venv exists
if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Please create it with: python -m venv .venv"
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install package with dev dependencies
echo "Installing package with development dependencies..."
pip install -e ".[dev]"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "Please edit .env with your Amazon Ads API credentials"
fi

# Create openapi directory if it doesn't exist
if [ ! -d "openapi" ]; then
    echo "Creating openapi directory..."
    mkdir -p openapi
fi

echo ""
echo "Setup complete! Next steps:"
echo "1. Edit .env with your Amazon Ads API credentials"
echo "2. Run 'source .venv/bin/activate' to activate the virtual environment"
echo "3. Run 'make run' to start the MCP server"