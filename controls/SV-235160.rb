# frozen_string_literal: true

control 'SV-235160' do
  title 'The MySQL Database Server 8.0 must protect its audit features from
unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data.

    Depending upon the log format and application, system and application log
tools may provide the only means to manipulate and manage application and
system log data. It is, therefore, imperative that access to audit tools be
controlled and protected from unauthorized access.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys to make access decisions regarding the
access to audit tools.

    Audit tools include, but are not limited to, OS-provided audit tools,
vendor-provided audit tools, and open source audit tools needed to successfully
view and manipulate audit information system activity and records.

    If an attacker were to gain access to audit tools, he could analyze audit
logs for system weaknesses or weaknesses in the auditing itself. An attacker
could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', "Check users with permissions to administer MySQL Auditing.

    select * from information_schema.user_privileges where privilege_type =
'AUDIT_ADMIN';

    If unauthorized accounts have these the AUDIT_ADMIN privilege, this is a
finding."
  desc 'fix', 'Remove audit-related permissions from individuals and roles not authorized
to have them.

    REVOKE AUDIT_ADMIN on *.* FROM <user>;'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag gid: 'V-235160'
  tag rid: 'SV-235160r960939_rule'
  tag stig_id: 'MYS8-00-008000'
  tag fix_id: 'F-38342r623601_fix'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9', 'AU-9 a']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  audit_admins = if !input('aws_rds')
                   input('audit_admins')
                 else
                   input('audit_admins') + ["'rdsadmin'@'localhost'"]
                 end

  query_audit_admins = %(
  SELECT
     *
  FROM
     information_schema.user_privileges
  WHERE
     privilege_type = 'AUDIT_ADMIN';
  )

  describe 'AUDIT_ADMINs defined' do
    subject { sql_session.query(query_audit_admins).results.column('grantee') }
    it { should be_in audit_admins }
  end
end
