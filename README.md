# Oracle MySQL 8.0 STIG Automated Compliance Validation Profile

<b>Oracle MySQL 8.0</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>Oracle MySQL 8.0</b>.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>Oracle MySQL 8.0 STIG Automated Compliance Validation Profile</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.


## Oracle MySQL 8.0 STIG Overview

The <b>Oracle MySQL 8.0</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>Oracle MySQL 8.0</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the Oracle MySQL 8.0 STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This STIG Automated Compliance Validation Profile was developed based upon:

- Oracle MySQL 8.0 Security Technical Implementation Guide

### Update History

| Guidance Name                             | Guidance Version | Guidance Location                         | Profile Version | Profile Release Date | STIG EOL | Profile EOL |
| ----------------------------------------- | ---------------- | ----------------------------------------- | --------------- | -------------------- | -------- | ----------- |
| Oracle MySQL 8.0 Security STIG Benchmark | v1r1             | https://public.cyber.mil/stigs/downloads/ | 1.0.0           | 12/30/2021           | NA       | NA          |


## Getting Started

### Requirements

#### Oracle MySQL 8.0 
- Oracle MySQL 8.0  Database
- Target should contain mysql cli client.

#### Required software on InSpec Runner
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
dod_appoved_cert_issuer: DoD Root CA

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
Some default values have been added to `inspec.yml`, but can be overridden by defining new values in `inputs.yml`.

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
## Check Overview

**Normal Checks**

These checks will follow the normal automation process and will report accurate STIG compliance PASS/FAIL.

| Check Number | Description                                                                                                                                                                                                               |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SV-235189 | The MySQL Database Server 8.0 must implement NIST FIPS 140-2 validatedcryptographic modules to generate and validate cryptographic hashes. |
| SV-235188 | The MySQL Database Server 8.0 must implement NIST FIPS 140-2 validatedcryptographic modules to provision digital signatures. |
| SV-235099 | The audit information produced by the MySQL Database Server 8.0 mustbe protected from unauthorized read access. |
| SV-235154 | The MySQL Database Server 8.0 must maintain the authenticity ofcommunications sessions by guarding against man-in-the-middle attacks thatguess at Session ID values. |
| SV-235160 | The MySQL Database Server 8.0 must protect its audit features fromunauthorized access. |
| SV-235193 | The MySQL Database Server 8.0 must implement cryptographic mechanismspreventing the unauthorized disclosure of organization-defined information atrest on organization-defined information system components. |
| SV-235144 | Unused database components, MySQL Database Server 8.0 software, anddatabase objects must be removed. |
| SV-235135 | The MySQL Database Server 8.0 must enforce authorized access to allPKI private keys stored/utilized by the MySQL Database Server 8.0. |
| SV-235150 | The MySQL Database Server 8.0 must separate user functionality(including user interface services) from database management functionality. |
| SV-235101 | The audit information produced by the MySQL Database Server 8.0 mustbe protected from unauthorized deletion. |
| SV-235096 | MySQL Database Server 8.0  must limit the number of concurrentsessions to an organization-defined number per user for all accounts and/oraccount types. |
| SV-235187 | The MySQL Database Server 8.0 must use NSA-approved cryptography toprotect classified information in accordance with the data owner'srequirements. |
| SV-235134 | The MySQL Database Server 8.0, when utilizing PKI-basedauthentication, must validate certificates by performing RFC 5280-compliantcertification path validation. |
| SV-235100 | The audit information produced by the MySQL Database Server 8.0 mustbe protected from unauthorized modification. |
| SV-235097 | MySQL Database Server 8.0  must produce audit records containingsufficient information to establish what type of events occurred. |
| SV-235186 | The MySQL Database Server 8.0 must maintain the confidentiality andintegrity of information during preparation for transmission. |
| SV-235104 | The MySQL Database Server 8.0 must allow only the Information SystemSecurity Manager (ISSM) (or individuals or roles appointed by the ISSM) toselect which auditable events are to be audited. |
| SV-235155 | The MySQL Database Server 8.0 must protect the confidentiality andintegrity of all information at rest. |
| SV-235161 | The MySQL Database Server 8.0 must protect its audit configurationfrom unauthorized modification. |
| SV-235192 | The MySQL Database Server 8.0 must implement cryptographic mechanismsto prevent unauthorized modification of organization-defined information atrest (to include, at a minimum, PII and classified information) onorganization-defined information system components. |
| SV-235145 | Unused database components which are integrated in the MySQL DatabaseServer 8.0 and cannot be uninstalled must be disabled. |
| SV-235137 | If Database Management System (DBMS) authentication using passwords isemployed, the DBMS must enforce the DoD standards for password complexity andlifetime. |
| SV-235103 | The MySQL Database Server 8.0 must be configured to provide auditrecord generation capability for DoD-defined auditable events within alldatabase components. |
| SV-235191 | The MySQL Database Server 8.0 must only accept end entity certificatesissued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for theestablishment of all encrypted sessions. |
| SV-235162 | The MySQL Database Server 8.0 must protect its audit features fromunauthorized removal. |
| SV-235181 | The MySQL Database Server 8.0 must prevent non-privileged users fromexecuting privileged functions, to include disabling, circumventing, oraltering implemented security safeguards/countermeasures. |
| SV-235146 | The MySQL Database Server 8.0 must be configured to prohibit orrestrict the use of organization-defined functions, ports, protocols, and/orservices, as defined in the PPSM CAL and vulnerability assessments. |
| SV-235190 | The MySQL Database Server 8.0 must implement NIST FIPS 140-2 validatedcryptographic modules to protect unclassified information requiringconfidentiality and cryptographic protection, in accordance with the dataowner's requirements. |
| SV-235180 | Execution of software modules (to include stored procedures,functions, and triggers) with elevated privileges must be restricted tonecessary cases only. |
| SV-235194 | Security-relevant software updates to the MySQL Database Server 8.0must be installed within the time period directed by an authoritative source(e.g., IAVM, CTOs, DTMs, and STIGs). |
| SV-235167 | The MySQL Database Server 8.0 must disable network functions, ports,protocols, and services deemed by the organization to be nonsecure, in accordwith the Ports, Protocols, and Services Management (PPSM) guidance. |
| SV-235136 | The MySQL Database Server 8.0 must map the PKI-authenticated identityto an associated user account. |
| SV-235143 | Default demonstration and sample databases, database objects, andapplications must be removed. |
| SV-235095 | MySQL Database Server 8.0 must integrate with an organization-levelauthentication/access mechanism providing account management and automation forall users, groups, roles, and any other principals. |
| SV-235158 | The MySQL Database Server 8.0 and associated applications, when makinguse of dynamic code execution, must scan input data for invalid values that mayindicate a code injection attack. |
| SV-235148 | The MySQL Database Server 8.0 must use NIST FIPS 140-2 validatedcryptographic modules for cryptographic operations. |
| SV-235139 | If passwords are used for authentication, the MySQL Database Server8.0 must transmit only encrypted representations of passwords. |
| SV-235168 | The MySQL Database Server 8.0 must prohibit user installation of logicmodules (stored procedures, functions, triggers, views, etc.) without explicitprivileged status. |
| SV-235138 | If passwords are used for authentication, the MySQL Database Server8.0 must store only hashed, salted representations of passwords. |
| SV-235169 | The MySQL Database Server 8.0 must enforce access restrictionsassociated with changes to the configuration of the MySQL Database Server 8.0or database(s). |
| SV-235179 | The MySQL Database Server 8.0 must enforce discretionary accesscontrol policies, as defined by the data owner, over defined subjects andobjects. |
| SV-235159 | The MySQL Database Server 8.0 must initiate session auditing uponstartup. |


**Manual Checks**

The following cheks will require manual evaluation to validate target compliance. 


| Check Number | Description                                                                                                                                                                                                               |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SV-235098 | The MySQL Database Server 8.0 must include additional, more detailed,organizationally defined information in the audit records for audit eventsidentified by type, location, or subject. |
| SV-235105 | The MySQL Database Server 8.0 must be able to generate audit recordswhen privileges/permissions are retrieved. |
| SV-235131 | The MySQL Database Server 8.0 must be able to generate audit recordswhen successful accesses to objects occur. |
| SV-235183 | The MySQL Database Server 8.0 must associate organization-definedtypes of security labels having organization-defined security label values withinformation in process. |
| SV-235121 | The MySQL Database Server 8.0 must generate audit records whensecurity objects are deleted. |
| SV-235170 | The MySQL Database Server 8.0 must produce audit records of itsenforcement of access restrictions associated with changes to the configurationof the MySQL Database Server 8.0 or database(s). |
| SV-235115 | The MySQL Database Server 8.0 must generate audit records whensecurity objects are modified. |
| SV-235164 | The MySQL Database Server 8.0 software installation account must berestricted to authorized users. |
| SV-235111 | The MySQL Database Server 8.0 must generate audit records whenprivileges/permissions are added. |
| SV-235140 | The MySQL Database Server 8.0 must obscure feedback of authenticationinformation during the authentication process to protect the information frompossible exploitation/use by unauthorized individuals. |
| SV-235174 | The MySQL Database Server 8.0 must off-load audit data to a separatelog management facility; this must be continuous and in near real time forsystems with a network connection to the storage facility and weekly or moreoften for stand-alone systems. |
| SV-235125 | The MySQL Database Server 8.0 must generate audit records whensuccessful logons or connections occur. |
| SV-235165 | Database software, including MySQL Database Server 8.0 configurationfiles, must be stored in dedicated directories, or DASD pools (remove),separate from the host OS and other applications. |
| SV-235151 | The MySQL Database Server 8.0 must isolate security functions fromnon-security functions. |
| SV-235110 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to access categories of information (e.g., classificationlevels/security levels) occur. |
| SV-235141 | The MySQL Database Server 8.0 must enforce approved authorizations forlogical access to information and system resources in accordance withapplicable access control policies. |
| SV-235175 | The MySQL Database Server 8.0 must provide a warning to appropriatesupport staff when allocated audit record storage volume reaches 75 percent ofmaximum audit record storage capacity. |
| SV-235124 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to delete categories of information (e.g., classificationlevels/security levels) occur. |
| SV-235130 | The MySQL Database Server 8.0 must generate audit records whenconcurrent logons/connections by the same user from different workstations. |
| SV-235182 | The MySQL Database Server 8.0 must associate organization-definedtypes of security labels having organization-defined security label values withinformation in storage. |
| SV-235120 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to delete privileges/permissions occur. |
| SV-235171 | The MySQL Database Server 8.0 must utilize centralized management ofthe content captured in audit records generated by all components of the MySQLDatabase Server 8.0. |
| SV-235114 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to modify privileges/permissions occur. |
| SV-235195 | When invalid inputs are received, the MySQL Database Server 8.0 mustbehave in a predictable and documented manner that reflects organizational andsystem objectives. |
| SV-235166 | The role(s)/group(s) used to modify database structure (including butnot necessarily limited to tables, indexes, storage, etc.) and logic modules(stored procedures, functions, triggers, links to software external to theMySQL Database Server 8.0, etc.) must be restricted to authorized users. |
| SV-235152 | Database contents must be protected from unauthorized and unintendedinformation transfer by enforcement of a data-transfer policy. |
| SV-235142 | The MySQL Database Server 8.0 must be configured in accordance withthe security configuration settings based on DoD security configuration andimplementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs,and IAVMs. |
| SV-235113 | The MySQL Database Server 8.0 must generate audit records whenprivileges/permissions are modified. |
| SV-235127 | The MySQL Database Server 8.0 must generate audit records for allprivileged activities or other system-level access. |
| SV-235176 | The MySQL Database Server 8.0 must provide an immediate real-timealert to appropriate support staff of all audit log failures. |
| SV-235185 | The MySQL Database Server 8.0 must automatically terminate a usersession after organization-defined conditions or trigger events requiringsession disconnect. |
| SV-235156 | The MySQL Database Server 8.0 must check the validity of all datainputs except those specifically identified by the organization. |
| SV-235107 | The MySQL Database Server 8.0 must be able to generate audit recordswhen security objects are accessed. |
| SV-235133 | The MySQL Database Server 8.0 must generate audit records for alldirect access to the database(s). |
| SV-235172 | The MySQL Database Server 8.0 must provide centralized configurationof the content to be captured in audit records generated by all components ofthe MySQL Database Server 8.0. |
| SV-235123 | The MySQL Database Server 8.0 must generate audit records whencategories of information (e.g., classification levels/security levels) aredeleted. |
| SV-235117 | The MySQL Database Server 8.0 must generate audit records whencategories of information (e.g., classification levels/security levels) aremodified. |
| SV-235157 | The MySQL Database Server 8.0 and associated applications must reservethe use of dynamic code execution for situations that require it. |
| SV-235106 | The MySQL Database Server 8.0 must be able to generate audit recordswhen unsuccessful attempts to retrieve privileges/permissions occur. |
| SV-235132 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful accesses to objects occur. |
| SV-235163 | The MySQL Database Server 8.0 must limit privileges to change softwaremodules, to include stored procedures, functions and triggers, and links tosoftware external to the MySQL Database Server 8.0. |
| SV-235173 | The MySQL Database Server 8.0 must allocate audit record storagecapacity in accordance with organization-defined audit record storagerequirements. |
| SV-235122 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to delete security objects occur. |
| SV-235116 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to modify security objects occur. |
| SV-235147 | The MySQL Database Server 8.0 must uniquely identify and authenticateorganizational users (or processes acting on behalf of organizational users). |
| SV-235102 | The MySQL Database Server 8.0 must protect against a user falselyrepudiating having performed organization-defined actions. |
| SV-235153 | Access to database files must be limited to relevant processes and toauthorized, administrative users. |
| SV-235112 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to add privileges/permissions occur. |
| SV-235126 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful logons or connection attempts occur. |
| SV-235177 | The MySQL Database Server 8.0 must prohibit the use of cachedauthenticators after an organization-defined time period. |
| SV-235184 | The MySQL Database Server 8.0 must associate organization-definedtypes of security labels having organization-defined security label values withinformation in transmission. |
| SV-235109 | The MySQL Database Server 8.0 must generate audit records whencategories of information (e.g., classification levels/security levels) areaccessed. |
| SV-235119 | The MySQL Database Server 8.0 must generate audit records whenprivileges/permissions are deleted. |
| SV-235178 | The MySQL Database Server 8.0 must require users to reauthenticatewhen organization-defined circumstances or situations require reauthentication. |
| SV-235129 | The MySQL Database Server 8.0 must generate audit records showingstarting and ending time for user access to the database(s). |
| SV-235128 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to execute privileged activities or other system-levelaccess occur. |
| SV-235108 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to access security objects occur. |
| SV-235149 | The MySQL Database Server 8.0 must uniquely identify and authenticatenon-organizational users (or processes acting on behalf of non-organizationalusers). |
| SV-235118 | The MySQL Database Server 8.0 must generate audit records whenunsuccessful attempts to modify categories of information (e.g., classificationlevels/security levels) occur. |

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)