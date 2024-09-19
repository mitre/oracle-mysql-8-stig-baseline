control 'SV-265876' do
  title 'MySQL database products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.

Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Review the version and release information.

To check the version of the installed MySQL, run the following SQL statement:

select @@version;

The result will show the version. For example:
8.0.22-commercial

Access the vendor website or use other means to verify the version is still supported.
Oracle lifetime support: 
https://www.oracle.com/us/assets/lifetime-support-technology-069183.pdf
Scroll down to Oracle MySQL Releases (approximately page 28).

If the Oracle MySQL version or any of the software components are not supported by the vendor, this is a finding.'
  desc 'fix', 'Remove or decommission all unsupported software products.

Upgrade unsupported DBMS or unsupported components to a supported version of the product.'
  impact 0.7
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-69795r999532_chk'
  tag severity: 'high'
  tag gid: 'V-265876'
  tag rid: 'SV-265876r999534_rule'
  tag stig_id: 'MYS8-00-012600'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-69699r999533_fix'
  tag 'documentable'
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']
end
