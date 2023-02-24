# Oracle MySQL 8.0 STIG Automated Compliance Validation Profile

InSpec profile to validate the secure configuration of Oracle MySQL 8.0 against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Oracle MySQL 8.0 (STIG) Version 1 Release 1.

## Oracle MySQL 8.0 STIG Overview

The Oracle MySQL 8.0 STIG, created by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of the database. 
DISA created and maintains a set of security guidelines for applications, computer systems or networks connected to DOD.

[STIG](https://public.cyber.mil/stigs/)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA).

This InSpec profile automates the validation of Oracle MySQL 8.0 databases against the equivalent STIG.

## Getting Started

### Requirements

#### Oracle MySQL 8.0 
- Oracle MySQL 8.0  Database
- Target should contain mysql cli client.

#### Required software on InSpec Runner
- git
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on MySQL Database machine 
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.

#### Ensure InSpec version is most recent ( > 4.23.X )
```sh
inspec --version
```

### How to execute this instance  
This profile can be executed against a remote target using the ssh transport, docker transport, or winrm transport of InSpec. Profiles can also be executed directly on the host where InSpec is installed (see https://www.inspec.io/docs/reference/cli/). 

#### Required Inputs
You must specify inputs in an `inputs.yml` file. See `example_inputs.yml` in the profile root folder for a sample. Each input is required for proper execution of the profile.
```yaml
#Description: privileged account username MySQL DB Server
#Value Type: string
user: root

#Description: password specified user
#Value Type: string
password: mysqlrootpass

#Description: hostname of MySQL DB Server
#Value Type:
host: localhost

#Description: port MySQL DB Server
#Value Type: numeric
port: 3306

#Description: Wildcard based path to list all audit log files
#Value Type: string
audit_log_path: /var/lib/mysql/audit*log*

#Description: List of documented audit admin accounts.
#Value Type: array
audit_admins: ["'root'@'localhost'", "'root'@'%'"]

#Description: Name of the documented server cert issuer.
#Value Type: string
org_appoved_cert_issuer: DoD Root CA

#Description: List of documented accounts exempted from PKI authentication.
#Value Type: array
pki_exception_users: ["healthchecker"]

#Description: List of documented accounts allowed to login with password.
#Value Type: array
authorized_password_users: ["healthchecker"]

#Description: List of documented mysql accounts with administrative previlleges.
#Value Type: array
mysql_administrative_users: ["root"]

#Description: List of documented mysql administrative role grantees
#Value Type: array
mysql_administrative_grantees: ["'root'@'localhost'"]

#Description: max user connections allowed
#Value Type: numeric
max_user_connections: 50

#Description: List of approved Plugins
#Value Type: array
approved_plugins: ["audit_log"]

#Description: List of approved components
#Value Type: array
approved_components: ["file://component_validate_password"]

#Description: Authorized MySQL port definitions
#Value Type: Hash
mysql_ports:
  port: 3306
  admin_port: 33062
  mysqlx_port: 33060

#Description: Authorized MySQL socket definitions
#Value Type: Hash
mysql_sockets:
  socket: '/var/lib/mysql/mysql.sock'
  mysqlx_socket: '/var/run/mysqld/mysqlx.sock'

#Description: Location of the my.cnf file
#Value Type: string
mycnf: /etc/my.cnf

#Description: Location of the mysqld-auto.cnf file
#Value Type: string
mysqld_auto_cnf: /var/lib/mysql/auto.cnf

#Description: Location of the mysqld-auto.cnf file
#Value Type: array
authorized_procedures: []

#Description: Location of the mysqld-auto.cnf file
#Value Type: array
authorized_functions: []

#Description: Approved minimum version of MySQL
#Value Type: string
minimum_mysql_version: 8.0.25

```
Some default values have been added to `inspec.yml`, but can be overridden by defining new values in `inputs.yml` and passing that file to `inspec exec` at runtime.

#### Execute a single control in the profile 
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml --controls=SV-235096 -t <target>
```
#### Execute a single control in the profile and save results as JSON
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml --controls=<control id> -t <target> --reporter cli json:results.json
```
#### Execute all controls in the profile 
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml -t <target>
```
#### Execute all controls in the profile and save results as JSON
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml -t <target> --reporter cli json:results.json
```
#### Execute the profile directly on the MySQL database host
```bash
inspec exec <path to profile on the host> --input-file=inputs.yml --reporter cli json:results.json
```