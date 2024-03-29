control 'SV-235172' do
  title "The MySQL Database Server 8.0 must provide centralized configuration
of the content to be captured in audit records generated by all components of
the MySQL Database Server 8.0."
  desc  "If the configuration of the Database Management System's (DBMS's)
auditing is spread across multiple locations in the database management
software, or across multiple commands, only loosely related, it is harder to
use and takes longer to reconfigure in response to events.

    The DBMS must provide a unified tool for audit configuration.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation for a description of how audit records are
off-loaded and how local audit log space is managed.

    If the MySQL Server audit records are not written directly to or
systematically transferred to a centralized log management system, this is a
finding.
  "
  desc 'fix', "Configure and/or deploy software tools to ensure that MySQL
Server audit records are written directly to or systematically transferred to a
centralized log management system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000356-DB-000315'
  tag gid: 'V-235172'
  tag rid: 'SV-235172r638812_rule'
  tag stig_id: 'MYS8-00-009500'
  tag fix_id: 'F-38354r623637_fix'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']

  describe 'Manually review the system documentation for a description of how audit records are
off-loaded and how local audit log space is managed.' do
    skip 'Manually review the system documentation for a description of how audit records are
    off-loaded and how local audit log space is managed.'
  end
end
