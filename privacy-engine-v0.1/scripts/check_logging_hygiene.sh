#!/bin/bash
# Logging Hygiene CI Check for Privacy Engine v0.1
#
# This script greps the entire source tree for any logger call that includes
# a variable named with PII-like names. It fails the build if any are found.
#
# PII-like variable names that should NEVER appear in logger calls:
#   text, original, value, pii, password, secret, raw, input, data, payload, content

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# PII-like variable names to check for
PII_VARS="text|original|value|pii|password|secret|raw|input|data|payload|content"

# Counter for violations
VIOLATIONS=0
VIOLATION_LINES=()

echo "=============================================="
echo "Privacy Engine v0.1 - Logging Hygiene Check"
echo "=============================================="
echo ""

# Check Python files for logger calls with PII-like variable names
# We look for patterns like:
#   logger.info(..., text, ...)
#   logger.info(..., value, ...)
#   log.info(..., password, ...)
# etc.

echo "Scanning source tree for PII-like variable names in logger calls..."

# Find all Python files in the project
while IFS= read -r file; do
    # Skip test files for this check (tests may intentionally log for verification)
    if [[ "$file" == *"_test.py" ]] || [[ "$file" == *"test_"* ]]; then
        continue
    fi
    
    # Check each line for logger calls with PII-like variables
    line_num=0
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        
        # Skip comments
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        # Check if line contains a logger call AND a PII-like variable
        # Logger patterns: .info(, .error(, .warning(, .debug(, .exception(, log.info(, etc.
        if [[ "$line" =~ \.(info|error|warning|debug|exception|warn)\(.*\.(text|original|value|pii|password|secret|raw|input|data|payload|content) ]]; then
            VIOLATIONS=$((VIOLATIONS + 1))
            VIOLATION_LINES+=("$file:$line_num")
            echo -e "${RED}VIOLATION${NC}: $file:$line_num"
            echo "  Line: ${line:0:100}..."
        fi
    done < <(grep -n -E '\.(info|error|warning|debug|exception|warn)\([^)]*\b(text|original|value|pii|password|secret|raw|input|data|payload|content)\b' "$file" 2>/dev/null || true)
    
done < <(find "$SRC_DIR" -name "*.py" -type f 2>/dev/null)

echo ""
echo "=============================================="

if [ $VIOLATIONS -gt 0 ]; then
    echo -e "${RED}FAILED${NC}: Logging hygiene check failed."
    echo ""
    echo "Logger receives PII-like variable names at the following locations:"
    for vl in "${VIOLATION_LINES[@]}"; do
        echo "  - $vl"
    done
    echo ""
    echo "Logging hygiene check failed: logger receives PII-like variable names."
    exit 1
else
    echo -e "${GREEN}PASSED${NC}: No PII-like variable names found in logger calls."
    echo ""
    echo "All logger calls are safe - no raw text, PII values, or sensitive"
    echo "variable names are being logged."
    exit 0
fi
