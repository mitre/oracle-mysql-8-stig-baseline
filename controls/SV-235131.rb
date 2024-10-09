# frozen_string_literal: true

control 'SV-235131' do
  title 'The MySQL Database Server 8.0 must be able to generate audit records
when successful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected
objects (tables, views, procedures, functions, etc.), it would be difficult to
establish, correlate, and investigate the events relating to an incident, or
identify those responsible for one.

    In an SQL environment, types of access include, but are not necessarily
limited to:
    SELECT
    INSERT
    UPDATE
    DELETE
    EXECUTE'
  desc 'check', %q(Review the system documentation to determine if MySQL Server is required to generate audit records when successful accesses to objects occur.

Check if MySQL audit is configured and enabled. The my.cnf file will set the variable audit_file.

To further check, execute the following query:
SELECT PLUGIN_NAME, PLUGIN_STATUS
      FROM INFORMATION_SCHEMA.PLUGINS
      WHERE PLUGIN_NAME LIKE 'audit%';

The status of the audit_log plugin must be "active". If it is not "active", this is a finding.

Review audit filters and associated users by running the following queries:
SELECT `audit_log_filter`.`NAME`,
   `audit_log_filter`.`FILTER`
FROM `mysql`.`audit_log_filter`;

SELECT `audit_log_user`.`USER`,
   `audit_log_user`.`HOST`,
   `audit_log_user`.`FILTERNAME`
FROM `mysql`.`audit_log_user`;

All currently defined audits for the MySQL server instance will be listed. If no audits are returned, this is a finding.

To check if the audit filters in place are generating records to audit when certain objects are accessed:

Run a query and other access types on that object.
select * from <schemaname>/<tablename>;

Review the audit log by running the Linux command:
sudo cat  <directory where audit log files are located>/audit.log|egrep <tablename>
For example if the values returned by "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log
sudo cat  /usr/local/mysql/data/audit.log |egrep <tablename>

If the audit event is not present, this is a finding.)
  desc 'fix', 'Configure the MySQL Database Server to audit when successful accesses to
objects occur.

    See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000507-DB-000356'
  tag gid: 'V-235131'
  tag rid: 'SV-235131r961836_rule'
  tag stig_id: 'MYS8-00-004400'
  tag fix_id: 'F-38313r623514_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  audit_log_plugin = if !input('aws_rds')
                       %(
    SELECT
       PLUGIN_NAME,
       plugin_status
    FROM
       INFORMATION_SCHEMA.PLUGINS
    WHERE
       PLUGIN_NAME LIKE 'audit_log' ;
    )
                     else
                       %(
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
    # If ANY of the automatable tests FAIL, the control will report automated statues
    # If ALL automatable tests PASS, MANUAL review statuses are reported to ensure full compliance

    if !audit_log_plugin_status.results.column('plugin_status').join.eql?('ACTIVE') ||
       audit_log_filter_entries.results.empty? ||
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

    describe 'Community Server server_audit_events settings' do
      subject { Set[server_audit_events_setting.results.column('value')[0].split(',')] }
      it { should cmp Set['CONNECT,QUERY'.split(',')] }
    end

  end
end
