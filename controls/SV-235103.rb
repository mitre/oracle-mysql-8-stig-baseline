control 'SV-235103' do
  title "The MySQL Database Server 8.0 must be configured to provide audit
record generation capability for #{input('org_name')}-defined auditable events within all
database components."
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the Database
Management System (DBMS) (e.g., process, module). Certain specific application
functionalities may be audited as well. The list of audited events is the set
of events for which audits are to be generated. This set of events is typically
a subset of the list of all events for which the system is capable of
generating audit records.

    #{input('org_name')} has defined the list of events for which the DBMS will provide an audit
record generation capability as the following:

    (i) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    (ii) Access actions, such as successful and unsuccessful logon attempts,
privileged activities, or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system; and

    (iii) All account creation, modification, disabling, and termination
actions.

    Organizations may define additional events requiring continuous or ad hoc
auditing.
  "
  desc  'rationale', ''
  desc  'check', "
    Check MySQL auditing to determine whether organization-defined auditable
events are being audited by the system.

    SELECT PLUGIN_NAME, plugin_status FROM INFORMATION_SCHEMA.PLUGINS
           WHERE PLUGIN_NAME LIKE 'audit_log' ;
          
[NOTE: The STIG guidance is based on MySQL 8 Enterprise Edition. 
Community Server (also used by AWS RDS) has reduced or different features. 
For Community Server, the MariaDB audit plugin may be used. 
This InSpec profile is adapted to measure accordingly when using Community Server:    
    SELECT PLUGIN_NAME, plugin_status FROM INFORMATION_SCHEMA.PLUGINS
          WHERE PLUGIN_NAME LIKE 'SERVER_AUDIT' ;]

    If nothing is returned OR if the results are not \"audit_log\" and
\"plugin_status='ACTIVE'\" , this is a finding.

    Next determine if the audit lot is encrypted.
    SELECT VARIABLE_NAME, VARIABLE_VALUE
    FROM performance_schema.global_variables
    WHERE VARIABLE_NAME LIKE 'audit_log_encryption' ;

    If nothing is returned OR the value for audit_log_encryption is not
\"AES\", this is a finding.
[NOTE: Community Server using MariaDB audit plugin does not support the audit_log_encryption parameter]
  "
  desc 'fix', "
    Deploy a MySQL Database Server 8.0 that supports the #{input('org_name')} minimum set of
auditable events.

    Configure the MySQL Database Server 8.0 to generate audit records for at
least the #{input('org_name')} minimum set of events.

    sudo vi /etc/my.cnf
    [mysqld]
    audit-log=FORCE_PLUS_PERMANENT
    audit-log-format=JSON
    audit-log-encryption=AES

    After changing the my.cnf, restart the server.

    SELECT audit_log_encryption_password_set(password);

    Create auditing rules - for example:
    Connect to MySQL and Use functions to define audit rules and audited users
audit_log_filter_set,audit_log_filter_set_user

    To log all auditable events:
    SELECT audit_log_filter_set_filter('log_all', '{ \"filter\": { \"log\":
true } }');

    And to apply this log_all filter to all users:
    SELECT audit_log_filter_set_user('%', 'log_all');
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: 'V-235103'
  tag rid: 'SV-235103r638812_rule'
  tag stig_id: 'MYS8-00-001600'
  tag fix_id: 'F-38285r623430_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  if !input('aws_rds')
    audit_log_plugin = %(
    SELECT
       PLUGIN_NAME,
       plugin_status 
    FROM
       INFORMATION_SCHEMA.PLUGINS 
    WHERE
       PLUGIN_NAME LIKE 'audit_log' ;
    )
  else
    audit_log_plugin = %(
    SELECT
       PLUGIN_NAME,
       plugin_status 
    FROM
       INFORMATION_SCHEMA.PLUGINS 
    WHERE
       PLUGIN_NAME LIKE 'SERVER_AUDIT' ;
    )
  end
  
  audit_log_encryption = %(
  SELECT
     VARIABLE_NAME,
     VARIABLE_VALUE 
  FROM
     performance_schema.global_variables 
  WHERE
     VARIABLE_NAME LIKE 'audit_log_encryption' ;
  )

    describe "Audit Log Plugin status" do
      subject { sql_session.query(audit_log_plugin).results.column('plugin_status') }
      it { should cmp 'ACTIVE' }
    end
  
  if !input('aws_rds')

    describe "audit_log_encryption config" do
      subject { sql_session.query(audit_log_encryption).results.column('variable_value') }
      it { should cmp 'AES' }
    end
    
  end
end
