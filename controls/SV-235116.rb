control 'SV-235116' do
  title "The MySQL Database Server 8.0 must generate audit records when
unsuccessful attempts to modify security objects occur."
  desc  "Changes in the database objects (tables, views, procedures, functions)
that record and control permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized changes to the
security subsystem could go undetected. The database could be severely
compromised or rendered inoperative.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation to determine if MySQL Server is required to
audit when unsuccessful attempts to modify security objects occur.

    Check if MySQL audit is configured and enabled. The my.cnf file will set
the variable audit_file.

    To further check, execute the following query:
    SELECT PLUGIN_NAME, PLUGIN_STATUS
          FROM INFORMATION_SCHEMA.PLUGINS
          WHERE PLUGIN_NAME LIKE 'audit%';

[NOTE: The STIG guidance is based on MySQL 8 Enterprise Edition. 
Community Server (also used by AWS RDS) has reduced or different features. 
For Community Server, the MariaDB audit plugin may be used. 
This InSpec profile is adapted to measure accordingly when using Community Server:
    Verify the plugin installation by running:
    SELECT PLUGIN_NAME, PLUGIN_STATUS
           FROM INFORMATION_SCHEMA.PLUGINS
           WHERE PLUGIN_NAME LIKE 'SERVER%';
    The value for SERVER_AUDIT should return ACTIVE.]

    The status of the audit_log plugin must be \"active\". If it is not
\"active\", this is a finding.

[NOTE: The STIG guidance is based on MySQL 8 Enterprise Edition. 
Community Server (also used by AWS RDS) has reduced or different features. 
For Community Server, the MariaDB audit plugin may be used and configured to 
audit all CONNECT and QUERY events.
This InSpec profile is adapted to measure accordingly when using Community Server:
    Verify the CONNECT and QUERY events are enabled:
    SHOW variables LIKE 'server_audit_events';
    +---------------------+---------------+
    | Variable_name       | Value         |
    +---------------------+---------------+
    | server_audit_events | CONNECT,QUERY |
    +---------------------+---------------+
  	1 row in set (0.00 sec)    
  	The value for server_audit_events should return CONNECT,QUERY.]

    Review audit filters and associated users by running the following queries:
    SELECT `audit_log_filter`.`NAME`,
       `audit_log_filter`.`FILTER`
    FROM `mysql`.`audit_log_filter`;

    SELECT `audit_log_user`.`USER`,
       `audit_log_user`.`HOST`,
       `audit_log_user`.`FILTERNAME`
    FROM `mysql`.`audit_log_user`;

    All currently defined audits for the MySQL server instance will be listed.
If no audits are returned, this is a finding.

    To check if the audit filters in place are generating records when
unsuccessful attempts to modify security objects occur, run the following as a
user without administrator-level privileges:
    update mysql.global_grants set host='%' where PRIV='XXXX’;

    Review the audit log by running the Linux command:
    sudo cat  <directory where audit log files are located>/audit.log|egrep
global_grants
    For example if the values returned by - \"select @@datadir,
@@audit_log_file; \" are  /usr/local/mysql/data/,  audit.log
    sudo cat  /usr/local/mysql/data/audit.log |egrep global_grants

    The audit data will look similar to the example below and contain a
non-zero status value:
    { \"timestamp\": \"2020-08-19 21:32:27\", \"id\": 2, \"class\":
\"general\", \"event\": \"status\", \"connection_id\": 9, \"account\": {
\"user\": \"root\", \"host\": \"localhost\" }, \"login\": { \"user\": \"root\",
\"os\": \"\", \"ip\": \"::1\", \"proxy\": \"\" }, \"general_data\": {
\"command\": \"Query\", \"sql_command\": \"update\", \"query\": \"update
mysql.global_grants set host='%' where PRIV='XXXX'\", \"status\": 1421 } }

    If the audit event is not present, this is a finding.
  "
  desc 'fix', "
    If currently required, configure the MySQL Database Server to produce audit
records when unsuccessful attempts to modify security objects occur.

    See the supplemental file \"MySQL80Audit.sql\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag gid: 'V-235116'
  tag rid: 'SV-235116r638812_rule'
  tag stig_id: 'MYS8-00-002900'
  tag fix_id: 'F-38298r623469_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

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

  audit_log_plugin_status = sql_session.query(audit_log_plugin)

  query_audit_log_filter = %(
  SELECT
     audit_log_filter.NAME,
     audit_log_filter.FILTER
  FROM
     mysql.audit_log_filter;
  )

  audit_log_filter_entries = sql_session.query(query_audit_log_filter)

  query_audit_log_user = %(
  SELECT
     audit_log_user.USER,
     audit_log_user.HOST,
     audit_log_user.FILTERNAME
  FROM
     mysql.audit_log_user;
  )

  audit_log_user_entries = sql_session.query(query_audit_log_user)

  query_server_audit_events = %(SHOW variables LIKE 'server_audit_events';)

  server_audit_events_setting = sql_session.query(query_server_audit_events)


  if !input('aws_rds')
  
    # Following code design will allow for adaptive tests in this partially automatable control
    # If ANY of the automatable tests FAIL, the control will report automated statuses
    # If ALL automatable tests PASS, MANUAL review statuses are reported to ensure full compliance

    if !audit_log_plugin_status.results.column('plugin_status').join.eql?('ACTIVE') or
       audit_log_filter_entries.results.empty? or
       audit_log_user_entries.results.empty?

      describe 'Audit Log Plugin status' do
        subject { audit_log_plugin_status.results.column('plugin_status') }
        it { should cmp 'ACTIVE' }
      end

      describe 'List of entries in Table: audit_log_filter' do
        subject { audit_log_filter_entries.results }
        it { should_not be_empty }
      end

      describe 'List of entries in Table: audit_log_user' do
        subject { audit_log_user_entries.results }
        it { should_not be_empty }
      end
    end

    describe "Manually validate `audit_log` plugin is active:\n #{audit_log_plugin_status.output}" do
      skip "Manually validate `audit_log` plugin is active:\n #{audit_log_plugin_status.output}"
    end
    describe "Manually review table `audit_log_filter` contains required entries:\n #{audit_log_filter_entries.output}" do
      skip "Manually review table `audit_log_filter` contains required entries:\n #{audit_log_filter_entries.output}"
    end
    describe "Manually review table `audit_log_user` contains required entries:\n #{audit_log_user_entries.output}" do
      skip "Manually review table `audit_log_user` contains required entries:\n #{audit_log_user_entries.output}"
    end
    describe 'Manually validate that required audit logs are generated when the specified query is executed.' do
      skip 'Manually validate that required audit logs are generated when the specified query is executed.'
    end
    
  else
    
    describe 'Audit Log Plugin status' do
      subject { audit_log_plugin_status.results.column('plugin_status') }
      it { should cmp 'ACTIVE' }
    end

    if audit_log_plugin_status.results.column('plugin_status').join.eql?('ACTIVE')
      describe 'Community Server server_audit_events settings' do
        subject { Set[server_audit_events_setting.results.column('value')[0].split(',')] }
        it { should cmp Set['CONNECT,QUERY'.split(',')] }
      end
    end
  end
end
