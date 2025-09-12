#!/bin/bash

# Script to install dependencies for all social media clones
set -euo pipefail

# Color variables for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICES=("facebook" "instagram" "x" "default")

echo -e "${YELLOW}Installing dependencies for all services...${NC}"

for service in "${SERVICES[@]}"; do
    if [ -d "$ROOT_DIR/$service" ]; then
        echo -e "\n${YELLOW}Installing dependencies for $service...${NC}"
        cd "$ROOT_DIR/$service"
        
        if [ -f "package.json" ]; then
            echo -e "${GREEN}Found package.json, installing npm dependencies...${NC}"
            npm install
            
            # Check if tailwind is a dependency and run its initialization if needed
            if grep -q "tailwindcss" "package.json"; then
                echo -e "${YELLOW}Setting up Tailwind CSS...${NC}"
                if [ ! -f "tailwind.config.js" ]; then
                    # Create basic tailwind config
                    echo 'module.exports = {
  content: ["./**/*.{html,js}"],
  theme: {
    extend: {},
  },
  plugins: [],
}' > tailwind.config.js
                    echo -e "${GREEN}Created tailwind.config.js${NC}"
                fi
            fi
        else
            echo -e "${RED}No package.json found in $service directory${NC}"
        fi
    else
        echo -e "${RED}Directory $service not found${NC}"
    fi
done

echo -e "\n${GREEN}All dependencies have been installed!${NC}"
