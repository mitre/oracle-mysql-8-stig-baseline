control 'SV-235130' do
  title "The MySQL Database Server 8.0 must generate audit records when
concurrent logons/connections by the same user from different workstations."
  desc  "For completeness of forensic analysis, it is necessary to track who
logs on to the Database Management System (DBMS).

    Concurrent connections by the same user from multiple workstations may be
valid use of the system; or such connections may be due to improper
circumvention of the requirement to use the CAC for authentication; or they may
indicate unauthorized account sharing; or they may be because an account has
been compromised.

    (If the fact of multiple, concurrent logons by a given user can be reliably
reconstructed from the log entries for other events (logons/connections;
voluntary and involuntary disconnections), then it is not mandatory to create
additional log entries specifically for this).
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation to determine if MySQL Server is required to
audit the concurrent logons/connections by the same user from different
workstations.

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
multiple connections occur:

    Run multiple connections from the same user without logging out and from
different IP addresses.

    Review the audit log:
    sudo cat  <directory where audit log files are located>/audit.log | egrep
<username>
    For example if the values returned by - \"select @@datadir,
@@audit_log_file; \" are  /usr/local/mysql/data/,  audit.log and the user is
fewconnects then
    sudo cat  /usr/local/mysql/data/audit.log |egrep fewconnects

     { \"connection_type\": \"ssl\", \"status\": 0, \"db\": \"\",
\"connection_attributes\": { \"_pid\": \"9132\", \"_os\": \"macos10.14\",
\"_platform\": \"x86_64\", \"_client_version\": \"8.0.20\", \"_client_name\":
\"libmysql\", \"program_name\": \"mysqlsh\" } } },
    { \"timestamp\": \"2020-08-31 18:03:41\", \"id\": 0, \"class\":
\"connection\", \"event\": \"connect\", \"connection_id\": 28, \"account\": {
\"user\": \"fewconnects\", \"host\": \"localhost\" }, \"login\": { \"user\":
\"fewconnects\", \"os\": \"\", \"ip\": \"\", \"proxy\": \"\" },
\"connection_data\": { \"connection_type\": \"ssl\", \"status\": 0, \"db\":
\"\", \"connection_attributes\": { \"_pid\": \"9132\", \"_os\": \"macos10.14\",
\"_platform\": \"x86_64\", \"_client_version\": \"8.0.20\", \"_client_name\":
\"libmysql\", \"program_name\": \"mysqlsh\" } } }
    { \"timestamp\": \"2020-08-31 18:11:05\", \"id\": 12, \"class\":
\"connection\", \"event\": \"connect\", \"connection_id\": 38, \"account\": {
\"user\": \"fewconnects\", \"host\": \"localhost\" }, \"login\": { \"user\":
\"fewconnects\", \"os\": \"\", \"ip\": \"93.122.141.147\", \"proxy\": \"\" },
\"connection_data\": { \"connection_type\": \"ssl\", \"status\": 0, \"db\":
\"\", \"connection_attributes\": { \"_pid\": \"903\", \"_os\": \"macos10.15\",
\"_platform\": \"x86_64\", \"_client_version\": \"8.0.20\", \"_client_name\":
\"libmysql\", \"program_name\": \"MySQLWorkbench\" } } },
    Note that each connection has a different connection_id - indicating
distinctly auditing multiple connections. Here there are connections from
mysqlsh and MySQLWorkbench; the event type is \"event\": “connect” and the
\"user\": \"fewconnects\", \"os\": \"\", \"ip\": “127.0.0.1” and \"login\": {
\"user\": \"fewconnects\", \"os\": \"\", \"ip\": “93.122.141.147” - that is
with different IPs from the different workstations.

    If the audit events are not present, this is a finding.

    If currently required, configure the MySQL Database Server to produce audit
records when connections occur.

    See the supplemental file \"MySQL80Audit.sql\".
  "
  desc 'fix', "
    If currently required, configure the MySQL Database Server to produce audit
records when connections occur.

    See the supplemental file \"MySQL80Audit.sql\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag gid: 'V-235130'
  tag rid: 'SV-235130r638812_rule'
  tag stig_id: 'MYS8-00-004300'
  tag fix_id: 'F-38312r623511_fix'
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
end
