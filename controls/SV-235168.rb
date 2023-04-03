control 'SV-235168' do
  title "The MySQL Database Server 8.0 must prohibit user installation of logic
modules (stored procedures, functions, triggers, views, etc.) without explicit
privileged status."
  desc  "Allowing regular users to install software, without explicit
privileges, creates the risk that untested or potentially malicious software
will be installed on the system. Explicit privileges (escalated or
administrative privileges) provide the regular user with explicit capabilities
and control that exceed the rights of a regular user.

    Database Management System (DBMS) functionality and the nature and
requirements of databases will vary; so while users are not permitted to
install unapproved software, there may be instances where the organization
allows the user to install approved software packages such as from an approved
software repository. The requirements for production servers will be more
restrictive than those used for development and research.

    The DBMS must enforce software installation by users based upon what types
of software installations are permitted (e.g., updates and security patches to
existing software) and what types of installations are prohibited (e.g.,
software whose pedigree with regard to being potentially malicious is unknown
or suspect) by the organization.

    In the case of a DBMS, this requirement covers stored procedures,
functions, triggers, views, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    MySQL requires users (other than root) to be explicitly granted the CREATE
ROUTINE privilege in order to install logical modules.

    To obtain a listing of users and roles who are authorized to create, alter,
or replace stored procedures and functions from the server documentation.

    Execute the following query:

    For server level permissions
    SELECT `user`.`Host`,
        `user`.`User`
    FROM `mysql`.`user`
     where     `Create_routine_priv`='Y' OR
        `Alter_routine_priv` = 'Y';

    If any users or role permissions returned are not authorized to modify the
specified object or type, this is a finding.

    If any user or role membership is not authorized, this is a finding.

    For database schema level permission (db is the schema name)
    SELECT `db`.`Host`,
        `db`.`User`,
        `db`.`Db`
    FROM `mysql`.`db` where     `db`.`Create_routine_priv`='Y' OR
        `db`.`Alter_routine_priv` = 'Y';

    If any users or role permissions returned are not authorized to modify the
specified object or type, this is a finding.

    If any user or role membership is not authorized, this is a finding.
  "
  desc 'fix', "
    MySQL requires users (other than root) to be explicitly granted the CREATE
ROUTINE privilege in order to install logical modules.

    Check user grants using the SHOW GRANTS and look for appropriate assignment
of CREATE ROUTINE.

    For example - REVOKE CREATE ROUTINE ON mydb.* TO 'someuser'@'somehost';
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag gid: 'V-235168'
  tag rid: 'SV-235168r638812_rule'
  tag stig_id: 'MYS8-00-009100'
  tag fix_id: 'F-38350r623625_fix'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  if !input('aws_rds')
    mysql_administrative_users = input('mysql_administrative_users')
  else
    mysql_administrative_users = input('mysql_administrative_users') + ['rdsadmin']
  end

  query_users = %(
  SELECT
     user.Host,
     user.User 
  FROM
     mysql.user 
  where
     Create_routine_priv = 'Y' 
     OR Alter_routine_priv = 'Y';
  )

  query_schema_permissions = %(
  SELECT
     db.Host,
     db.User,
     db.Db 
  FROM
     mysql.db 
  where
     db.Create_routine_priv = 'Y' 
     OR db.Alter_routine_priv = 'Y';
  )

  describe "List of authorized to create, alter,
or replace stored procedures and functions." do
    subject { sql_session.query(query_users).results.column('user') }
    it { should be_in mysql_administrative_users }
  end

  describe "List of users or role permissions returned are authorized to modify the
specified object or type." do
    subject { sql_session.query(query_schema_permissions).results.column('user') }
    it { should be_in mysql_administrative_users }
  end
end
