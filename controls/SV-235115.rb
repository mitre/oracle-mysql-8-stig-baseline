control 'SV-235115' do
  title "The MySQL Database Server 8.0 must generate audit records when
security objects are modified."
  desc  "Changes in the database objects (tables, views, procedures, functions)
that record and control permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized changes to the
security subsystem could go undetected. The database could be severely
compromised or rendered inoperative."
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation to determine if MySQL Server is required to
audit when security objects are modified.

    Check if MySQL audit is configured and enabled. The my.cnf file will set
the variable audit_file.

    To further check, execute the following query:
    SELECT PLUGIN_NAME, PLUGIN_STATUS
          FROM INFORMATION_SCHEMA.PLUGINS
          WHERE PLUGIN_NAME LIKE 'audit%';

    The status of the audit_log plugin must be \"active\". If it is not
\"active\", this is a finding.

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

    To check if the audit filters that are in place are generating records when
security objects are modified, run the following, which will test auditing
without destroying data:
    update mysql.global_grants set host='%' where PRIV='XXXX’;

    Review the audit log by running the Linux command:
    sudo cat  <directory where audit log files are located>/audit.log|egrep
global_grants
    For example if the values returned by \"select @@datadir, @@audit_log_file;
\" are  /usr/local/mysql/data/,  audit.log
    sudo cat  /usr/local/mysql/data/audit.log |egrep global_grants
    For example if the values returned by \"select @@datadir, @@audit_log_file;
\" are  /usr/local/mysql/data/,  audit.log
    sudo cat  /usr/local/mysql/data/audit.log |egrep global_grants

    The audit data will look similar to the example below:
    { \"timestamp\": \"2020-08-19 21:32:27\", \"id\": 2, \"class\":
\"general\", \"event\": \"status\", \"connection_id\": 9, \"account\": {
\"user\": \"root\", \"host\": \"localhost\" }, \"login\": { \"user\": \"root\",
\"os\": \"\", \"ip\": \"::1\", \"proxy\": \"\" }, \"general_data\": {
\"command\": \"Query\", \"sql_command\": \"update\", \"query\": \"update
mysql.global_grants set host='%' where PRIV='XXXX'\", \"status\": 0 } }

    If the audit event is not present, this is a finding.
  "
  desc 'fix', "
    If currently required, configure the MySQL Database Server to produce audit
records when security objects are modified.

    See the supplemental file \"MySQL80Audit.sql\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag gid: 'V-235115'
  tag rid: 'SV-235115r638812_rule'
  tag stig_id: 'MYS8-00-002800'
  tag fix_id: 'F-38297r623466_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  audit_log_plugin = %(
  SELECT
     PLUGIN_NAME,
     plugin_status
  FROM
     INFORMATION_SCHEMA.PLUGINS
  WHERE
     PLUGIN_NAME LIKE 'audit_log' ;
  )

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

  # Following code design will allow for adaptive tests in this partially automatable control
  # If ANY of the automatable tests FAIL, the control will report automated statues
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
    skip
  end
  describe "Manually review table `audit_log_filter` contains required entries:\n #{audit_log_filter_entries.output}" do
    skip
  end
  describe "Manually review table `audit_log_user` contains required entries:\n #{audit_log_user_entries.output}" do
    skip
  end
  describe 'Manually validate that required audit logs are generated when the specified query is executed.' do
    skip
  end
end
