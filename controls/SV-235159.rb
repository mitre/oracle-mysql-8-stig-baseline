control 'SV-235159' do
  title "The MySQL Database Server 8.0 must initiate session auditing upon
startup."
  desc  "Session auditing is for use when a user's activities are under
investigation. To be sure of capturing all activity during those periods when
session auditing is in use, it needs to be in operation for the whole time the
Database Management System (DBMS) is running."
  desc  'rationale', ''
  desc  'check', "
    Determine if an audit is configured and enabled.

    The my.cnf file will set the variable audit_file.

    Review the my.cnf file for the following entries:
    [mysqld]
    plugin-load-add=audit_log.so
    audit-log=FORCE_PLUS_PERMANENT

    If these entries are not present. This is a finding.

    Execute the following query:
    SELECT PLUGIN_NAME, PLUGIN_STATUS
           FROM INFORMATION_SCHEMA.PLUGINS
           WHERE PLUGIN_NAME LIKE 'audit%';

    The status of the \"audit_log plugin\" must be \"active\". If it is not
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
  "
  desc 'fix', "
    Configure the MySQL Audit to automatically start during system startup.
    Add to the my.cnf:

    [mysqld]
    plugin-load-add=audit_log.so
    audit-log=FORCE_PLUS_PERMANENT
    audit-log-format=JSON
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag gid: 'V-235159'
  tag rid: 'SV-235159r638812_rule'
  tag stig_id: 'MYS8-00-007800'
  tag fix_id: 'F-38341r623598_fix'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  mycnf = input('mycnf')

  describe ini(mycnf) do
    its ('mysqld.plugin-load-add') { should cmp 'audit_log.so' }
    its ('mysqld.audit-log') { should cmp 'FORCE_PLUS_PERMANENT' }
  end

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

  describe 'Audit Log Plugin status' do
    subject { audit_log_plugin_status.results.column('plugin_status').join }
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
