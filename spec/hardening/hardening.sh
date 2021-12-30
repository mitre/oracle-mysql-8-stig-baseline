#!/bin/bash

# Apply file ownership reqs
chmod 0644 /etc/my.cnf
chmod 0750  /var/lib/mysql/
chgrp mysql /var/lib/mysql/

# Configure firewall plugin
mysql -u root -pmysqlrootpass < /usr/share/mysql-8.0/linux_install_firewall.sql

# Run custom hardening scripts
mysql -u root -pmysqlrootpass < /opt/hardening/hardening.sql

