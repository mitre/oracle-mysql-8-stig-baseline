control 'SV-235111' do
  title "The MySQL Database Server 8.0 must generate audit records when
privileges/permissions are added."
  desc  "Changes in the permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized elevation or
restriction of individuals and groups privileges could go undetected. Elevated
privileges give users access to information and functionality that they must
not have; restricted privileges wrongly deny access to authorized users.

    In a SQL environment, adding permissions is typically done via the GRANT
command, or, in the negative, the DENY command.
  "
  desc  'rationale', ''
  desc  'check', "
    Check that MySQL Server Audit is being used for the STIG compliant audit.

    Check if MySQL audit is configured and enabled. The my.cnf file will set
the variable audit_file.

    To further check, execute the following query:
    SELECT PLUGIN_NAME, PLUGIN_STATUS
          FROM INFORMATION_SCHEMA.PLUGINS
          WHERE PLUGIN_NAME LIKE 'audit%';

    The status of the audit_log plugin should be \"active\". If it is not
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

    Determine if rules are in place to capture the following types of commands
related to permissions by running the command:
    select * from mysql.audit_log_filter;

    If the template SQL filter was used, it will have the name log_stig.

    Review the filter value. It will show filters for events of the  type field
general_sql_command.str for the following SQL statement types:
    grant
    grant_roles
    revoke
    revoke_all
    revoke_roles
    drop_role
    alter_user_default_role
    create_role
    drop_role
    grant_roles
    revoke_roles
    set_role
    create_user
    alter_user
    drop_user
    alter_user
    alter_user_default_role
    create_user
    drop_user
    rename_user
    show_create_user
  "
  desc 'fix', "
    Configure the MySQL Database Server to audit when privileges/permissions
are added.

    Add the following events to the MySQL Server Audit being used for the STIG
compliance audit:
    grant
    grant_roles
    revoke
    revoke_all
    revoke_roles
    drop_role
    alter_user_default_role
    create_role
    drop_role
    grant_roles
    revoke_roles
    set_role
    create_user
    alter_user
    drop_user
    alter_user
    alter_user_default_role
    create_user
    drop_user
    rename_user
    show_create_user

    See the supplemental file \"MySQL80Audit.sql\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag gid: 'V-235111'
  tag rid: 'SV-235111r638812_rule'
  tag stig_id: 'MYS8-00-002400'
  tag fix_id: 'F-38293r623454_fix'
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
end
