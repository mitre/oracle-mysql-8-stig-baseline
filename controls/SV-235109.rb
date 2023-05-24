control 'SV-235109' do
  title "The MySQL Database Server 8.0 must generate audit records when
categories of information (e.g., classification levels/security levels) are
accessed."
  desc  "Changes in categories of information must be tracked. Without an audit
trail, unauthorized access to protected data could go undetected.

    For detailed information on categorizing information, refer to FIPS
Publication 199, Standards for Security Categorization of Federal Information
and Information Systems, and FIPS Publication 200, Minimum Security
Requirements for Federal Information and Information Systems.
  "
  desc  'rationale', ''
  desc  'check', "
    If classification levels/security levels labeling is not required, this is
not a finding.

    Review the system documentation to determine if MySQL Server is required to
audit records when unsuccessful attempts to delete categories of information
(e.g., classification levels/security levels) occur.

    Check if MySQL audit is configured and enabled. The my.cnf file will set
the variable audit_file.

    To further check, execute the following query:
    SELECT PLUGIN_NAME, PLUGIN_STATUS
          FROM INFORMATION_SCHEMA.PLUGINS
          WHERE PLUGIN_NAME LIKE 'audit%';

[NOTE: The STIG guidance is based on MySQL 8 Enterprise Edition. 
Community Server (also used by AWS RDS) has reduced or different features. 
For Community Server, the MariaDB audit plugin may be used. 
This InSpec profile is adapted to measure accordingly when using Community Server:
    Verify the plugin installation by running:
    SELECT PLUGIN_NAME, PLUGIN_STATUS
           FROM INFORMATION_SCHEMA.PLUGINS
           WHERE PLUGIN_NAME LIKE 'SERVER%';
    The value for audit_log should return ACTIVE.]

    The status of the audit_log plugin must be \"active\". If it is not
\"active\", this is a finding.

[NOTE: The STIG guidance is based on MySQL 8 Enterprise Edition. 
Community Server (also used by AWS RDS) has reduced or different features. 
For Community Server, the MariaDB audit plugin may be used and configured to 
audit all CONNECT and QUERY events.
This InSpec profile is adapted to measure accordingly when using Community Server:
    Verify the CONNECT and QUERY events are enabled:
    SHOW variables LIKE 'server_audit_events';
    +---------------------+---------------+
    | Variable_name       | Value         |
    +---------------------+---------------+
    | server_audit_events | CONNECT,QUERY |
    +---------------------+---------------+
  	1 row in set (0.00 sec)    
  	The value for server_audit_events should return CONNECT,QUERY.]
  
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

    Modify MySQL selects that check for changes to categories of information.
Modify selects statements to audit when information categories are accessed
using MySQL Audit by calling the audit_api_message_emit_udf() function and
including the details related to the select.

    - An Example test -

    CREATE TABLE `test_trigger`.`info_cat_test` (
      `id` INT NOT NULL,
      `name` VARCHAR(20) NULL,
      `desc` VARCHAR(20) NULL,
      `sec_level` CHAR(1) NULL,
      PRIMARY KEY (`id`));

    DELIMITER $$


    INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`,
`sec_level`) VALUES ('1', 'fred', 'engineer', 'H');
    INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`,
`sec_level`) VALUES ('2', 'jill', 'program manager', 'M');
    INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`,
`sec_level`) VALUES ('3', 'joe', 'maintenance', 'L');

    SELECT `info_cat_test`.`id`,
        `info_cat_test`.`name`,
        `info_cat_test`.`desc`,
        `info_cat_test`.`sec_level`,
        IF(`info_cat_test`.`sec_level`= 'H',
        audit_api_message_emit_udf('sec_level_selected',
                                             'audit_select_attempt',
                                             ' H level sec data was accessed',
                                             'FOR ', name
                                             ),
        'Not Audited')
    FROM `test_trigger`.`info_cat_test`;

    Review the audit log by running the Linux command:
    sudo cat  <directory where audit log files are located>/audit.log | egrep
sec_level_selected
    For example if the values returned by - \"select @@datadir,
@@audit_log_file; \" are  /usr/local/mysql/data/,  audit.log
    sudo cat  /usr/local/mysql/data/audit.log |egrep sec_level_priv

    The audit data will look similar to the example below:
    { \"timestamp\": \"2020-08-20 21:19:21\", \"id\": 1, \"class\":
\"message\", \"event\": \"user\", \"connection_id\": 9, \"account\": {
\"user\": \"root\", \"host\": \"localhost\" }, \"login\": { \"user\": \"root\",
\"os\": \"\", \"ip\": \"::1\", \"proxy\": \"\" }, \"message_data\": {
\"component\": \"sec_level_selected\", \"producer\": \"audit_select_attempt\",
\"message\": \" H level sec data was accessed\", \"map\": { \"FOR \": \"fred\"
} } },

    If the audit event is not present, this is a finding.
  "
  desc 'fix', "
    If currently required, configure the MySQL Database Server with stored
procedures that use selects that call audit_api_message_emit_udf() function to
produce audit records when selection of categories of information occurs.
    Add security level details in an additional column.

    Add the component for adding information to the audit log.

    INSTALL COMPONENT \"file://component_audit_api_message_emit”;
    create schema test_trigger;

    Modify selections adding the audit_api_message_emit_udf to be called, as
well as providing the details for the audit event.

    Transparently enforcing the use of MySQL stored procedures is required.

    See the supplemental file \"MySQL80Audit.sql\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000494-DB-000344'
  tag gid: 'V-235109'
  tag rid: 'SV-235109r638812_rule'
  tag stig_id: 'MYS8-00-002200'
  tag fix_id: 'F-38291r623448_fix'
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
    describe "Manually validate that required audit logs are generated when the following query is executed:
    CREATE TABLE `test_trigger`.`info_cat_test` ( `id` INT NOT NULL, `name` VARCHAR(20) NULL, `desc` VARCHAR(20) NULL, `sec_level` CHAR(1) NULL, PRIMARY KEY (`id`));
    DELIMITER $$ 
    INSERT INTO
       `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) 
    VALUES
       (
          '1', 'fred', 'engineer', 'H'
       )
    ;
    INSERT INTO
       `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) 
    VALUES
       (
          '2', 'jill', 'program manager', 'M'
       )
    ;
    INSERT INTO
       `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) 
    VALUES
       (
          '3', 'joe', 'maintenance', 'L'
       )
    ;
    SELECT
       `info_cat_test`.`id`,
       `info_cat_test`.`name`,
       `info_cat_test`.`desc`,
       `info_cat_test`.`sec_level`,
       IF(`info_cat_test`.`sec_level` = 'H', audit_api_message_emit_udf('sec_level_selected', 'audit_select_attempt', ' H level sec data was accessed', 'FOR ', name ), 'Not Audited') 
    FROM
       `test_trigger`.`info_cat_test`;" do
      skip "Manually validate that required audit logs are generated when the following query is executed:
      CREATE TABLE `test_trigger`.`info_cat_test` ( `id` INT NOT NULL, `name` VARCHAR(20) NULL, `desc` VARCHAR(20) NULL, `sec_level` CHAR(1) NULL, PRIMARY KEY (`id`));
      DELIMITER $$ 
      INSERT INTO
         `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) 
      VALUES
         (
            '1', 'fred', 'engineer', 'H'
         )
      ;
      INSERT INTO
         `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) 
      VALUES
         (
            '2', 'jill', 'program manager', 'M'
         )
      ;
      INSERT INTO
         `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) 
      VALUES
         (
            '3', 'joe', 'maintenance', 'L'
         )
      ;
      SELECT
         `info_cat_test`.`id`,
         `info_cat_test`.`name`,
         `info_cat_test`.`desc`,
         `info_cat_test`.`sec_level`,
         IF(`info_cat_test`.`sec_level` = 'H', audit_api_message_emit_udf('sec_level_selected', 'audit_select_attempt', ' H level sec data was accessed', 'FOR ', name ), 'Not Audited') 
      FROM
         `test_trigger`.`info_cat_test`;" 
    end
    
  else
    
    describe '[NOTE: The STIG guidance is based on MySQL 8 Enterprise Edition. Community Server (also used by AWS RDS) has reduced or different features. For Community Server, the MariaDB audit plugin may be used and configured to audit all CONNECT and QUERY events. Provide an attestation explaining how the type of events identified in this requirement are flagged by processes reading its generated audit logs.]' do
      skip '[NOTE: The STIG guidance is based on MySQL 8 Enterprise Edition. Community Server (also used by AWS RDS) has reduced or different features. For Community Server, the MariaDB audit plugin may be used and configured to audit all CONNECT and QUERY events. Provide an attestation explaining how the type of events identified in this requirement are flagged by processes reading its generated audit logs.]'
    end
  
  end
    
end
