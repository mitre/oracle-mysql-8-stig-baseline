control 'SV-235170' do
  title "The MySQL Database Server 8.0 must produce audit records of its
enforcement of access restrictions associated with changes to the configuration
of the MySQL Database Server 8.0 or database(s)."
  desc  "Without auditing the enforcement of access restrictions against
changes to configuration, it would be difficult to identify attempted attacks
and an audit trail would not be available for forensic investigation for
after-the-fact actions.

    Enforcement actions are the methods or mechanisms used to prevent
unauthorized changes to configuration settings. Enforcement action methods may
be as simple as denying access to a file based on the application of file
permissions (access restriction). Audit items may consist of lists of actions
blocked by access restrictions or changes identified after the fact.
  "
  desc  'rationale', ''
  desc  'check', "
    Determine if an audit is configured to capture denied actions.

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

    Connect and run commands as a low-privilege user. For example attempt to
change system variables, user name, or another user's password, all of which
should fail:
    set persist wait_timeout=28000;
    rename user passme to cantchange;
    SET PASSWORD FOR passme = 'sfsdfsdf';

    Review the audit log and inspect event data containing identity and user
subject details by running the Linux command:
    sudo cat  <directory where audit log files are located>/audit.log
    For example if the values returned by \"select @@datadir, @@audit_log_file;
\" are  /usr/local/mysql/data/,  audit.log
    sudo cat  /usr/local/mysql/data/audit.log

    { \"timestamp\": \"2020-08-31 20:10:21\", \"id\": 1, \"class\":
\"general\", \"event\": \"status\", \"connection_id\": 38, \"account\": {
\"user\": \"fewconnects\", \"host\": \"localhost\" }, \"login\": { \"user\":
\"fewconnects\", \"os\": \"\", \"ip\": \"127.0.0.1\", \"proxy\": \"\" },
\"general_data\": { \"command\": \"Query\", \"sql_command\": \"set_option\",
\"query\": \"set persist wait_timeout=28000\", \"status\": 1227 } },
    { \"timestamp\": \"2020-08-31 20:10:48\", \"id\": 1, \"class\":
\"general\", \"event\": \"status\", \"connection_id\": 38, \"account\": {
\"user\": \"fewconnects\", \"host\": \"localhost\" }, \"login\": { \"user\":
\"fewconnects\", \"os\": \"\", \"ip\": \"127.0.0.1\", \"proxy\": \"\" },
\"general_data\": { \"command\": \"Query\", \"sql_command\": \"rename_user\",
\"query\": \"rename user passme to cantchange\", \"status\": 1227 } },
    , \"host\": \"localhost\" }, \"login\": { \"user\": \"fewconnects\",
\"os\": \"\", \"ip\": \"127.0.0.1\", \"proxy\": \"\" }, \"general_data\": {
\"command\": \"Query\", \"sql_command\": \"set_password\", \"query\": \"SET
PASSWORD FOR `passme`@`%`=<secret>\", \"status\": 1044 } },
    Note each has a non-zero status, 1227, 1227, and 1044 respectively.

    If the audit log does not contain records of its enforcement of access
restrictions associated with changes to the configuration of the DBMS or
database(s), this is a finding.
  "
  desc 'fix', "
    If currently required, configure the MySQL Database Server to produce audit
records when enforcement of access restrictions is associated with changes to
the configuration of the DBMS or database(s).

    See the supplemental file \"MySQL80Audit.sql\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag gid: 'V-235170'
  tag rid: 'SV-235170r638812_rule'
  tag stig_id: 'MYS8-00-009300'
  tag fix_id: 'F-38352r623631_fix'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']

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
end
