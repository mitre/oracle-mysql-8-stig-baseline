control 'SV-235127' do
  title "The MySQL Database Server 8.0 must generate audit records for all
privileged activities or other system-level access."
  desc  "Without tracking privileged activity, it would be difficult to
establish, correlate, and investigate the events relating to an incident or
identify those responsible for one.

    System documentation should include a definition of the functionality
considered privileged.

    A privileged function in this context is any operation that modifies the
structure of the database, its built-in logic, or its security settings. This
would include all Data Definition Language (DDL) statements and all
security-related statements. In a SQL environment, it encompasses, but is not
necessarily limited to:
    CREATE
    ALTER
    DROP
    GRANT
    REVOKE
    DENY

    There may also be Data Manipulation Language (DML) statements that, subject
to context, should be regarded as privileged. Possible examples in SQL include:

    TRUNCATE TABLE;
    DELETE, or
    DELETE affecting more than n rows, for some n, or
    DELETE without a WHERE clause;

    UPDATE or
    UPDATE affecting more than n rows, for some n, or
    UPDATE without a WHERE clause;

    any SELECT, INSERT, UPDATE, or DELETE to an application-defined security
table executed by other than a security principal.

    Depending on the capabilities of the DBMS and the design of the database
and associated applications, audit logging may be achieved by means of Database
Management System (DBMS) auditing features, database triggers, other
mechanisms, or a combination of these.

    Note that it is particularly important to audit, and tightly control, any
action that weakens the implementation of this requirement itself, since the
objective is to have a complete audit trail of all administrative activity.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation to determine if MySQL Server is required to
audit for all privileged activities or other system-level access.

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

    Determine if rules are in place to capture the following types of commands
related to permissions by running:
    select * from mysql.audit_log_filter;

    If the template SQL filter was used, it will have the name \"log_stig\".

    Review the filter values. It will show filters for events of the type of
the field general_sql_command.str for the following SQL statement types:
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
    Configure the MySQL Database Server to audit for all privileged activities
or other system-level access.

    Add the following events to the MySQL Server Audit:
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
  tag gtitle: 'SRG-APP-000504-DB-000354'
  tag gid: 'V-235127'
  tag rid: 'SV-235127r638812_rule'
  tag stig_id: 'MYS8-00-004000'
  tag fix_id: 'F-38309r623502_fix'
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
end
