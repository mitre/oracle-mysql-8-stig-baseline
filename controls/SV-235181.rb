# frozen_string_literal: true

control 'SV-235181' do
  title 'The MySQL Database Server 8.0 must prevent non-privileged users from
executing privileged functions, to include disabling, circumventing, or
altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions
mitigates the risk that unauthorized individuals or processes may gain
unnecessary access to information or privileges.

    System documentation should include a definition of the functionality
considered privileged.

    Depending on circumstances, privileged functions can include, for example,
establishing accounts, performing system integrity checks, or administering
cryptographic key management activities. Non-privileged users are individuals
that do not possess appropriate authorizations. Circumventing intrusion
detection and prevention mechanisms or malicious code protection mechanisms are
examples of privileged functions that require protection from non-privileged
users.

    A privileged function in the Database Management System (DBMS)/database
context is any operation that modifies the structure of the database, its
built-in logic, or its security settings. This would include all Data
Definition Language (DDL) statements and all security-related statements. In a
SQL environment, it encompasses, but is not necessarily limited to:
    CREATE
    ALTER
    DROP
    GRANT
    REVOKE
    DENY

    There may also be Data Manipulation Language (DML) statements that, subject
to context, should be regarded as privileged. Possible examples include:

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
and associated applications, the prevention of unauthorized use of privileged
functions may be achieved by means of DBMS security features, database
triggers, other mechanisms, or a combination of these.'
  desc 'check', "Review the server documentation to obtain a listing of accounts used for
executing external processes. Execute the following query to obtain a listing
of accounts currently configured for use by external processes.

    SHOW PROCEDURE STATUS where security_type <> 'INVOKER';
    SHOW FUNCTION STATUS where security_type <> 'INVOKER';

    If DEFINER accounts are returned that are not documented and authorized,
this is a finding.
    If elevation of MySQL privileges using DEFINER is documented, but not
implemented as described in the documentation, this is a finding.
    If the privilege-elevation logic can be invoked in ways other than
intended, or in contexts other than intended, or by subjects/principals other
than intended, this is a finding."
  desc 'fix', 'Remove any procedures that are not authorized.

Drop the procedure or function using
DROP PROCEDURE <proc_name>;
DROP FUNCTION <function_name>;'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag gid: 'V-235181'
  tag rid: 'SV-235181r961353_rule'
  tag stig_id: 'MYS8-00-010700'
  tag fix_id: 'F-38363r623664_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  query_procedures = %(SHOW PROCEDURE STATUS where security_type <> 'INVOKER';)

  query_functions = %(SHOW FUNCTION STATUS where security_type <> 'INVOKER';)

  authorized_procedures = if !input('aws_rds')
                            input('authorized_procedures')
                          else
                            input('authorized_procedures') + ['rds_collect_global_status_history', 'rds_disable_gsh_collector', 'rds_disable_gsh_rotation', 'rds_enable_gsh_collector', 'rds_enable_gsh_rotation', 'rds_external_master', 'rds_innodb_buffer_pool_dump_now', 'rds_innodb_buffer_pool_load_abort', 'rds_innodb_buffer_pool_load_now', 'rds_kill', 'rds_kill_query', 'rds_next_master_log', 'rds_reset_external_master', 'rds_rotate_general_log', 'rds_rotate_global_status_history', 'rds_rotate_slow_log', 'rds_set_configuration', 'rds_set_external_master', 'rds_set_external_master_with_auto_position', 'rds_set_external_master_with_delay', 'rds_set_fk_checks_off', 'rds_set_fk_checks_on', 'rds_set_gsh_collector', 'rds_set_gsh_rotation', 'rds_set_master_auto_position', 'rds_set_source_delay', 'rds_show_configuration', 'rds_skip_repl_error', 'rds_skip_transaction_with_gtid', 'rds_start_replication', 'rds_start_replication_until', 'rds_start_replication_until_gtid', 'rds_stop_replication']
                          end

  authorized_functions = input('authorized_functions')

  describe 'List of PROCEDUREs defined' do
    subject { sql_session.query(query_procedures).results.column('name') }
    it { should be_in authorized_procedures }
  end

  describe 'List of FUNCTIONs defined' do
    subject { sql_session.query(query_functions).results.column('name') }
    it { should be_in authorized_functions }
  end
end
