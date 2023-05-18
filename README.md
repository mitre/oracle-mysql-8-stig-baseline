# Oracle MySQL 8.0 STIG Automated Compliance Validation Profile

InSpec profile to validate the secure configuration of Oracle MySQL 8.0 against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Oracle MySQL 8.0 (STIG) Version 1 Release 1.

#### AWS-RDS-Ready: Profile updated to adapt checks when running against an AWS RDS instance of MySQL, by setting the input `aws_rds` to `true`. See [Tailoring to Your Environment](#tailoring-to-your-environment) below.

## Getting Started

### Requirements

#### Oracle MySQL 8.0 
- Oracle MySQL 8.0  Database
- Target should contain mysql cli client.

#### Required software on InSpec Runner
- git
- [InSpec](https://www.chef.io/products/chef-inspec/)

#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.

#### Ensure InSpec version is most recent ( > 4.23.X )
```sh
inspec --version
```

### How to execute this instance  
This profile can be executed against a remote target using the ssh transport, docker transport, or winrm transport of InSpec. Profiles can also be executed directly on the host where InSpec is installed (see https://www.inspec.io/docs/reference/cli/). 

## Tailoring to Your Environment

The following inputs may be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
#Description: State if your database is an AWS RDS instance
#Value type: Boolean
aws_rds: false
 
#Description: privileged account username MySQL DB Server
#Value Type: string
user: (example) root

#Description: password specified user
#Value Type: string
password: (example) mysqlrootpass

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

#Description: List of documented authorized local mysql accounts. # SV-235095
#Value Type: array
mysql_authorized_local_users: ['root']

#Description: List of documented accounts allowed to login with password.
#Value Type: array
authorized_password_users: ["healthchecker"]

#Description: List of documented mysql accounts with administrative privileges.
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

#### Execute a single control in the profile 
```bash
inspec exec <path to profile on runner> --input-file=<name of your inputs file>.yml --controls=SV-235096 -t <target>
```
#### Execute a single control in the profile and save results as JSON
```bash
inspec exec <path to profile on runner> --input-file=<name of your inputs file>.yml --controls=<control id> -t <target> --reporter cli json:results.json
```
#### Execute all controls in the profile 
```bash
inspec exec <path to profile on runner> --input-file=<name of your inputs file>.yml -t <target>
```
#### Execute all controls in the profile and save results as JSON
```bash
inspec exec <path to profile on runner> --input-file=<name of your inputs file>.yml -t <target> --reporter cli json:results.json
```
#### Execute the profile directly on the MySQL database host
```bash
inspec exec <path to profile on the host> --input-file=<name of your inputs file>.yml --reporter cli json:results.json
```
