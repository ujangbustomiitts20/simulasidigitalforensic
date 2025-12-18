#!/bin/bash
# Startup script untuk victim container

# Start services
service rsyslog start
service ssh start
service apache2 start

# Keep container running
tail -f /var/log/apache2/access.log
