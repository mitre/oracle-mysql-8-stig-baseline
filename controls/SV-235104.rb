control 'SV-235104' do
  title "The MySQL Database Server 8.0 must allow only the Information System
Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to
select which auditable events are to be audited."
  desc  "Without the capability to restrict which roles and individuals can
select which events are audited, unauthorized personnel may be able to prevent
or interfere with the auditing of critical events.

    Suppression of auditing could permit an adversary to evade detection.

    Misconfigured audits can degrade the system's performance by overwhelming
the audit log. Misconfigured audits may also make it more difficult to
establish, correlate, and investigate the events relating to an incident or
identify those responsible for one.

    AUDIT_ADMIN enables audit log configuration. This privilege is defined by
the audit_log plugin when it is installed.
    SUPER is a powerful and far-reaching privilege and should not be granted
lightly.
  "
  desc  'rationale', ''
  desc  'check', "
    Check MySQL settings and documentation to determine whether designated
personnel are able to select which auditable events are being audited.

    To list out users who have rights to administrative access for auditing,
run this query:
    SELECT * FROM INFORMATION_SCHEMA.USER_PRIVILEGES where PRIVILEGE_TYPE in
('AUDIT_ADMIN', 'SUPER');

    If any of the roles or users returned have permissions that are not
documented, or the documented audit maintainers do not have permissions, this
is a finding.
  "
  desc 'fix', "
    Configure the MySQL Database Server 8.0 settings to allow designated
personnel to select which auditable events are audited.

    Grant permissions to users who need rights to create auditing rules.

    GRANT AUDIT_ADMIN
    ON *.* TO '<auditusername>'@'<host_specification>';

    For example:
    GRANT AUDIT_ADMIN
    ON *.* TO 'auditusername'@'%';
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag gid: 'V-235104'
  tag rid: 'SV-235104r638812_rule'
  tag stig_id: 'MYS8-00-001700'
  tag fix_id: 'F-38286r623433_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  # Test then implement for all other user inputs
  if !input('aws_rds')
    audit_admins = input('audit_admins')
  else
    audit_admins = input('audit_admins').concat(["'rdsadmin'@'localhost'"])


  query_audit_admins = %(
    SELECT
     * 
  FROM
     INFORMATION_SCHEMA.USER_PRIVILEGES 
  where
     PRIVILEGE_TYPE in 
     (
        'AUDIT_ADMIN',
        'SUPER'
     );
  )

  describe "List of configured audit admins" do
    subject { sql_session.query(query_audit_admins).results.column('grantee') }
    it { should match_array audit_admins }
  end
end
