control 'SV-235162' do
  title 'The MySQL Database Server 8.0 must protect its audit features from
unauthorized removal.'
  desc 'Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data. Therefore, protecting audit tools
is necessary to prevent unauthorized operation on audit data.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the deletion of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.'
  desc 'check', "Check users with permissions to administer MySQL Auditing.

    select * from information_schema.user_privileges where privilege_type =
'AUDIT_ADMIN';

    If unauthorized accounts have these the AUDIT_ADMIN privilege, this is a
finding."
  desc 'fix', 'This requirement is a permanent finding and cannot be fixed. An
appropriate mitigation for the system must be implemented, but this finding
cannot be considered fixed.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag gid: 'V-235162'
  tag rid: 'SV-235162r960945_rule'
  tag stig_id: 'MYS8-00-008200'
  tag fix_id: 'F-38344r623607_fix'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  if !input('aws_rds')
    audit_admins = input('audit_admins')
  else
    audit_admins = input('audit_admins') + ["'rdsadmin'@'localhost'"]
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
