# frozen_string_literal: true

control 'SV-235180' do
  title 'Execution of software modules (to include stored procedures,
functions, and triggers) with elevated privileges must be restricted to
necessary cases only.'
  desc 'In certain situations, to provide required functionality, a Database
Management System (DBMS) needs to execute internal logic (stored procedures,
functions, triggers, etc.) and/or external code modules with elevated
privileges. However, if the privileges required for execution are at a higher
level than the privileges assigned to organizational users invoking the
functionality applications/programs, those users are indirectly provided with
greater privileges than assigned by organizations.

    Privilege elevation must be utilized only where necessary and protected
from misuse.'
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
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag gid: 'V-235180'
  tag rid: 'SV-235180r961359_rule'
  tag stig_id: 'MYS8-00-010600'
  tag fix_id: 'F-38362r623661_fix'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  query_procedures = %(SHOW PROCEDURE STATUS where security_type <> 'INVOKER';)

  query_functions = %(SHOW FUNCTION STATUS where security_type <> 'INVOKER';)

  authorized_functions = input('authorized_functions')

  authorized_procedures = if !input('aws_rds')
                            input('authorized_procedures')
                          else
                            input('authorized_procedures') + ['rds_collect_global_status_history', 'rds_disable_gsh_collector', 'rds_disable_gsh_rotation', 'rds_enable_gsh_collector', 'rds_enable_gsh_rotation', 'rds_external_master', 'rds_innodb_buffer_pool_dump_now', 'rds_innodb_buffer_pool_load_abort', 'rds_innodb_buffer_pool_load_now', 'rds_kill', 'rds_kill_query', 'rds_next_master_log', 'rds_reset_external_master', 'rds_rotate_general_log', 'rds_rotate_global_status_history', 'rds_rotate_slow_log', 'rds_set_configuration', 'rds_set_external_master', 'rds_set_external_master_with_auto_position', 'rds_set_external_master_with_delay', 'rds_set_fk_checks_off', 'rds_set_fk_checks_on', 'rds_set_gsh_collector', 'rds_set_gsh_rotation', 'rds_set_master_auto_position', 'rds_set_source_delay', 'rds_show_configuration', 'rds_skip_repl_error', 'rds_skip_transaction_with_gtid', 'rds_start_replication', 'rds_start_replication_until', 'rds_start_replication_until_gtid', 'rds_stop_replication']
                          end

  describe 'List of PROCEDUREs defined' do
    subject { sql_session.query(query_procedures).results.column('name') }
    it { should be_in authorized_procedures }
  end

  describe 'List of FUNCTIONs defined' do
    subject { sql_session.query(query_functions).results.column('name') }
    it { should be_in authorized_functions }
  end
end
