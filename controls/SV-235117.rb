control 'SV-235117' do
  title "The MySQL Database Server 8.0 must generate audit records when
categories of information (e.g., classification levels/security levels) are
modified."
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
audit records when deletion of categories of information (e.g., classification
levels/security levels) occurs.

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

    Create MySQL insert, update, and delete triggers that check for changes to
categories of information. If the trigger before data indicates an attempt to
delete such information, the trigger must be written to prevent the delete as
well as optionally write to the MySQL Audit by calling the
audit_api_message_emit_udf() function and including the details related to the
attempt. Note: To call from a trigger requires a minimal stored procedure as
well.

    Once the trigger has been created, check if the audit filters in place are
generating records when categories of information are deleted.

    - An Example test -

    CREATE TABLE `test_trigger`.`info_cat_test` (
      `id` INT NOT NULL,
      `name` VARCHAR(20) NULL,
      `desc` VARCHAR(20) NULL,
      `sec_level` CHAR(1) NULL,
      PRIMARY KEY (`id`));

    use test_trigger;

    DELIMITER $$

    CREATE TRIGGER test_trigger.audit_delete
        BEFORE DELETE ON `test_trigger`.`info_cat_test`
        FOR EACH ROW
    BEGIN
        IF OLD.sec_level = 'H' THEN
    \t    CALL audit_api_message_emit_sp(OLD.name);
        END IF;
    END$$
    DELIMITER ;

    DELIMITER $$

    CREATE TRIGGER audit_insert
        BEFORE INSERT ON `test_trigger`.`info_cat_test`
        FOR EACH ROW
    BEGIN
        IF NEW.sec_level = 'H' THEN
    \t    CALL audit_api_message_emit_sp(NEW.name);
        END IF;
    END$$
    DELIMITER ;

    DELIMITER $$

    CREATE TRIGGER audit_update
        BEFORE UPDATE ON `test_trigger`.`info_cat_test`
        FOR EACH ROW
    BEGIN
        IF OLD.sec_level = 'H' THEN
    \t    CALL audit_api_message_emit_sp(OLD.name);
        END IF;
    \tIF NEW.sec_level = 'H' THEN
    \t    CALL audit_api_message_emit_sp(NEW.name);
        END IF;
    END$$
    DELIMITER ;

    INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`,
`sec_level`) VALUES ('1', 'fred', 'engineer', 'H');
    INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`,
`sec_level`) VALUES ('2', 'jill', 'program manager', 'M');
    INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`,
`sec_level`) VALUES ('3', 'joe', 'maintenance', 'L');

    delete from `test_trigger`.`info_cat_test` where id=1;
    // this fails as the trigger defines that sec_level of H can not be deleted.

    update`test_trigger`.`info_cat_test`  set sec_level=‘H’   where id=2;
    delete from `test_trigger`.`info_cat_test` where id=3;

    Review the audit log by running the Linux command:
    sudo cat  <directory where audit log files are located>/audit.log | egrep
audit_change_attempt

    If the audit event is not present, this is a finding.
  "
  desc 'fix', "
    If currently required, configure the MySQL Database Server with update,
insert, and delete triggers that call audit_api_message_emit_udf() function  to
produce audit records when unsuccessful attempts to modify categories of
information occur.

    Add security level details in an additional column.

    Add the component for adding information to the audit log.

    INSTALL COMPONENT \"file://component_audit_api_message_emit”;
    create schema test_trigger;

    Create a stored procedure to allow the audit_api_message_emit_udf to be
called as well as providing the details for the audit event.

    DELIMITER $$

    CREATE PROCEDURE audit_api_message_emit_delete_sp(name CHAR(20))
    BEGIN
    \tDECLARE aud_msg VARCHAR(255);
    \tselect audit_api_message_emit_udf('sec_level_trigger',
                                             'TRIGGER audit_change_attempt',
                                             'Attempt was made to change H
level sec data',
                                             'FOR ', name
                                             ) into aud_msg;
    END$$
    DELIMITER ;

    See the supplemental file \"MySQL80Audit.sql\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000498-DB-000346'
  tag gid: 'V-235117'
  tag rid: 'SV-235117r638812_rule'
  tag stig_id: 'MYS8-00-003000'
  tag fix_id: 'F-38299r623472_fix'
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
  describe 'Manually validate that required audit logs are generated when the specified query is executed.' do
    skip 'Manually validate that required audit logs are generated when the specified query is executed.'
  end
end
