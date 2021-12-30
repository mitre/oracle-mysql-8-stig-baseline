control 'SV-235129' do
  title "The MySQL Database Server 8.0 must generate audit records showing
starting and ending time for user access to the database(s)."
  desc  "For completeness of forensic analysis, it is necessary to know how
long a user's (or other principal's) connection to the Database Management
System (DBMS) lasts. This can be achieved by recording disconnections, in
addition to logons/connections, in the audit logs.

    Disconnection may be initiated by the user or forced by the system (as in a
timeout) or result from a system or network failure. To the greatest extent
possible, all disconnections must be logged.
  "
  desc  'rationale', ''
  desc  'check', "
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
successful logons or connections occur, log in to MySQL and then log out.

    Below is an example using MySQL Shell:
    % mysqlsh —sql
     MySQL  SQL > \\connect newuser@localhost
    Creating a session to 'newuser@localhost'
     MySQL  localhost:33060+ ssl  SQL > \\quit
    Bye!

    Review the audit log by running the Linux command:
    \"status\": 0 for each indicates successful.
    \"connection_id\": 19 is the same as the connections process id and there
will be matching disconnect event with the same connection_id number. This can
be used to differentiate multiple connections using the same login.
    Each connect and disconnect has a timestamp tag with the time in
Coordinated Universal Time (UTC).

    sudo cat  <directory where audit log files are located>/audit.log | egrep
\"\\\"event\\\": \\”connect\\\"\"
    For example if the values returned by - \"select @@datadir,
@@audit_log_file; \" are  /usr/local/mysql/data/,  audit.log
    sudo cat  /usr/local/mysql/data/audit.log |egrep \"\\\"event\\\":
\\”connect\\\"\"

    The audit data will look similar to the example below:
    Logging in - connecting

    { \"timestamp\": \"2020-08-21 17:47:09\", \"id\": 0, \"class\":
\"connection\", \"event\": \"connect\", \"connection_id\": 19, \"account\": {
\"user\": \"newuser\", \"host\": \"localhost\" }, \"login\": { \"user\":
\"newuser\", \"os\": \"\", \"ip\": \"::1\", \"proxy\": \"\" },
\"connection_data\": { \"connection_type\": \"plugin\", \"status\": 0, \"db\":
\"\" } },

    Logging out - disconnection

    sudo cat  <directory where audit log files are located>/audit.log | egrep
\"\\\"event\\\": \\\"disconnect\\”\"

    { \"timestamp\": \"2020-08-21 17:47:11\", \"id\": 1, \"class\":
\"connection\", \"event\": \"disconnect\", \"connection_id\": 19, \"account\":
{ \"user\": \"newuser\", \"host\": \"localhost\" }, \"login\": { \"user\":
\"newuser\", \"os\": \"\", \"ip\": \"::1\", \"proxy\": \"\" },
\"connection_data\": { \"connection_type\": \"plugin\" } },
  "
  desc 'fix', "
    If currently required, configure the MySQL Database Server to produce audit
records when successful logons or connections occur.

    See the supplemental file \"MySQL80Audit.sql\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag gid: 'V-235129'
  tag rid: 'SV-235129r638812_rule'
  tag stig_id: 'MYS8-00-004200'
  tag fix_id: 'F-38311r623508_fix'
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
