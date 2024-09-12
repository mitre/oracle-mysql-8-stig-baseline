# Oracle MySQL 8.0 STIG Automated Compliance Validation Profile

InSpec profile to validate the secure configuration of Oracle MySQL 8.0 against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Oracle MySQL 8.0 (STIG) Version 1 Release 1.

#### AWS-RDS-Ready: Profile updated to adapt checks when running against an AWS RDS instance of MySQL, by setting the input `aws_rds` to `true`. See [Tailoring to Your Environment](#tailoring-to-your-environment) below.

[NOTE: The STIG guidance is based on MySQL 8 Enterprise Edition. 
Community Server (also used by AWS RDS) has reduced or different features. 
For Community Server, the MariaDB audit plugin may be used. 
This InSpec profile is adapted to measure accordingly when using Community Server]

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
### MySQL client setup

To run the MySQL profile against an AWS RDS Instance, InSpec expects the mysql client to be readily available on the same runner system it is installed on.
 
For example, to install the mysql client on a Linux runner host:
```
sudo yum install mysql-community-server
```
To confirm successful install of mysql:
```
which mysql
```
> sample output:  _/usr/bin/mysql_
```
mysql –-version
```		
> sample output:  *mysql  Ver 8.0.32 for Linux on x86_64 (MySQL Community Server - GPL)*

Test mysql connectivity to your AWS RDS instance from your InSpec runner host:
```
mysql -u <master user> -p<password>  -h <endpoint>.amazonaws.com -P 3306
```		
> sample output:
>
>  *Welcome to the MySQL monitor.  Commands end with ; or \g.*
>  *Your MySQL connection id is 4035*
>  *Server version: 8.0.32 Source distribution*
>
>  *Copyright (c) 2000, 2023, Oracle and/or its affiliates.*
>
>  *Oracle is a registered trademark of Oracle Corporation and/or its*
>  *affiliates. Other names may be trademarks of their respective*
>  *owners.*
>
>  *Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.*
>
>  *mysql> quit*
>
>  *Bye*

For installation of mysql client on other operating systems for your runner host, visit https://www.mysql.com/



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

#Description: List of documented accounts allowed to login with password.
#Value Type: array
authorized_password_users: ["healthchecker"]

#Description: List of documented mysql accounts with administrative privileges.# SV-235096 SV-235150 SV-235168 SV-235179
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
### How to execute this instance  
This profile can be executed against a remote target using the ssh transport, docker transport, or winrm transport of InSpec. Profiles can also be executed directly on the host where InSpec is installed (see https://www.inspec.io/docs/reference/cli/). 

## Running This Overlay Directly from Github against a hosted (non AWS RDS) instance of MySQL 8: 

Against a remote target using ssh (i.e., inspec installed on a separate runner host)
```bash
inspec exec https://github.com/mitre/oracle-mysql-8-stig-baseline/archive/main.tar.gz -t ssh://<target_username>:<target_password>@<target_ip>:<target_port> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

Against a remote target using a pem key (i.e., inspec installed on a separate runner host)
```bash
inspec exec https://github.com/mitre/oracle-mysql-8-stig-baseline/archive/main.tar.gz -t ssh://<target_username>@<target_ip>:<target_port> -i <PEM_KEY> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>  
```

Against a _**locally-hosted**_ instance (i.e., inspec installed on the target hosting the database)

```bash
inspec exec https://github.com/mitre/oracle-mysql-8-stig-baseline/archive/main.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

Against a _**docker-containerized**_ instance (i.e., inspec installed on the node hosting the container):
```
inspec exec https://github.com/mitre/oracle-mysql-8-stig-baseline/archive/main.tar.gz -t docker://<instance_id> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
## Running This Overlay Directly from Github against an AWS RDS instance of MySQL 8: 

```bash
inspec exec https://github.com/mitre/oracle-mysql-8-stig-baseline/archive/main.tar.gz --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```
## Running This Overlay from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/oracle-mysql-8-stig-baseline.git
inspec archive oracle-mysql-8-stig-baseline
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd oracle-mysql-8-stig-baseline
git pull
cd ..
inspec archive oracle-mysql-8-stig-baseline --overwrite
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall2)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Eugene Aronne - [ejaronne](https://github.com/ejaronne)

## Special Thanks
* Aaron Lippold - [aaronlippold](https://github.com/aaronlippold)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/oracle-mysql-8-stig-baseline/issues/new).




## Generalized execution cases:

#### Execute a single control in the profile 
```bash
inspec exec <path to profile> --input-file=<name of your inputs file>.yml --controls=SV-235096 -t <target>
```
#### Execute a single control in the profile and save results as JSON
```bash
inspec exec <path to profile> --input-file=<name of your inputs file>.yml --controls=<control id> -t <target> --reporter cli json:results.json
```
#### Execute all controls in the profile 
```bash
inspec exec <path to profile> --input-file=<name of your inputs file>.yml -t <target>
```
#### Execute all controls in the profile and save results as JSON
```bash
inspec exec <path to profile> --input-file=<name of your inputs file>.yml -t <target> --reporter cli json:results.json
```
#### Execute the profile directly on the MySQL database host
```bash
inspec exec <path to profile> --input-file=<name of your inputs file>.yml --reporter cli json:results.json
```
