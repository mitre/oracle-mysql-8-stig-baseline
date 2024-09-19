# frozen_string_literal: true

control 'SV-235142' do
  title 'The MySQL Database Server 8.0 must be configured in accordance with
the security configuration settings based on DoD security configuration and
implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring the Database Management System (DBMS) to implement
organization-wide security implementation guides and security checklists
ensures compliance with federal standards and establishes a common security
baseline across DoD that reflects the most restrictive security posture
consistent with operational requirements.

    In addition to this SRG, sources of guidance on security and information
assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs.
The DBMS must be configured in compliance with guidance from all such relevant
sources.'
  desc 'check', 'Review the MySQL documentation and configuration to determine it is
configured in accordance with DoD security configuration and implementation
guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.

    If the MySQL is not configured in accordance with security configuration
settings, this is a finding.'
  desc 'fix', 'Configure MySQL in accordance with security configuration settings by reviewing the Operation System and MySQL documentation and applying the necessary configuration parameters to meet the configurations required by the STIG, NSA configuration guidelines, CTOs, DTMs, and IAVMs.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-235142'
  tag rid: 'SV-235142r961863_rule'
  tag stig_id: 'MYS8-00-005500'
  tag fix_id: 'F-38324r623547_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe "Manually review the MySQL documentation and configuration to determine it is
configured in accordance with #{input('org_name')} security configuration and implementation
guidance, including STIGs, #{input('org_guidance')}" do
    skip "Manually review the MySQL documentation and configuration to determine it is
    configured in accordance with #{input('org_name')} security configuration and implementation
    guidance, including STIGs, #{input('org_guidance')}"
  end
end
