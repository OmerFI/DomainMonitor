#!/bin/bash

# Start DomainMonitor
echo "Starting DomainMonitor"
cd web
exec gunicorn "app:app" --bind "0.0.0.0:8000"
