control 'SV-235128' do
  title 'The MySQL Database Server 8.0 must generate audit records when
unsuccessful attempts to execute privileged activities or other system-level
access occur.'
  desc 'Without tracking privileged activity, it would be difficult to
establish, correlate, and investigate the events relating to an incident or
identify those responsible for one.

    System documentation should include a definition of the functionality
considered privileged.

    A privileged function in this context is any operation that modifies the
structure of the database, its built-in logic, or its security settings. This
would include all Data Definition Language (DDL) statements and all
security-related statements. In an SQL environment, it encompasses, but is not
necessarily limited to:
    CREATE
    ALTER
    DROP
    GRANT
    REVOKE
    DENY

    Note that it is particularly important to audit, and tightly control, any
action that weakens the implementation of this requirement itself, since the
objective is to have a complete audit trail of all administrative activity.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.'
  desc 'check', %q(Review the system documentation to determine if MySQL Server is required to audit for unsuccessful attempts to execute privileged activities or other system-level access.

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

Determine if rules are in place to capture the following types of commands related to permissions by running:

select * from mysql.audit_log_filter;

If the template SQL filter was used, it will have the name log_stig.

Review the filter values it will show filters for events of type of the field general_sql_command.str for the following SQL statement types:
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
show_create_user)
  desc 'fix', 'Configure the MySQL Database Server to audit for unsuccessful attempts to
execute privileged activities or other system-level access.

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

    See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag gid: 'V-235128'
  tag rid: 'SV-235128r961827_rule'
  tag stig_id: 'MYS8-00-004100'
  tag fix_id: 'F-38310r623505_fix'
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
