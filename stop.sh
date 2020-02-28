#!/bin/bash

echo ""
echo "Stopping SimpleHTTPServer on port 80"
kill -9 `ps -ef | grep SimpleHTTPServer | grep -v "grep" | tr -s " " | cut -d ' ' -f3`
echo ""
echo "Stopping smbserver share name \"share\""
kill -9 `ps -ef | grep smbserver | grep -v "grep" | tr -s " " | cut -d ' ' -f3`
echo ""