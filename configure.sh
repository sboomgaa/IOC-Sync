#!/usr/bin/env bash
set -euo pipefail

# 1. Add config.yaml and exports/ to .gitignore (if not already present)
touch .gitignore

grep -qxF "config.yaml" .gitignore || echo "config.yaml" >> .gitignore
grep -qxF "exports/" .gitignore || echo "exports/" >> .gitignore

# 2. Secure config.yaml permissions
if [[ -f "config.yaml" ]]; then
    chmod 600 config.yaml
    echo "Applied chmod 600 to config.yaml"
else
    echo "WARNING: config.yaml not found in current directory"
fi

# 3. Install Python dependencies
if [[ -f "requirements.txt" ]]; then
    pip install -r requirements.txt
else
    echo "ERROR: requirements.txt not found in current directory"
    exit 1
fi

echo "Setup completed successfully."
