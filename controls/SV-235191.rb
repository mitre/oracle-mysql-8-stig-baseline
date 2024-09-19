control 'SV-235191' do
  title 'The MySQL Database Server 8.0 must only accept end entity certificates
issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the
establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure they
have security controls and identity vetting procedures in place that are
sufficient for DoD systems to rely on the identity asserted in the certificate.
PKIs lacking sufficient security controls and identity vetting procedures risk
being compromised and issuing certificates that enable adversaries to
impersonate legitimate users.

    The authoritative list of DoD-approved PKIs is published at
https://cyber.mil/pki-pke/interoperability.

    This requirement focuses on communications protection for the DBMS session
rather than for the network packet.'
  desc 'check', 'To run MySQL in SSL mode, obtain a valid certificate signed by a single
certificate authority.

    Before starting the MySQL database in SSL mode, verify the certificate used
is issued by a valid DoD certificate authority.

    Run this command:
    openssl x509 -in <path_to_certificate_pem_file> -text | grep -i "issuer"

    If there is any issuer present in the certificate that is not a
DoD-approved certificate authority, this is a finding.'
  desc 'fix', "Remove any certificate that was not issued by a valid DoD certificate
authority.

    Contact the organization's certificate issuer and request a new certificate
that is issued by a valid DoD certificate authorities."
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag gid: 'V-235191'
  tag rid: 'SV-235191r961596_rule'
  tag stig_id: 'MYS8-00-011900'
  tag fix_id: 'F-38373r623694_fix'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

  if !input('aws_rds')

    sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

    org_approved_cert_issuer = input('org_approved_cert_issuer')

    query_ssl_params = %(
    SELECT @@datadir,
          @@ssl_cert;
    )

    ssl_params = sql_session.query(query_ssl_params).results

    full_cert_path = "#{ssl_params.column('@@datadir').join}#{ssl_params.column('@@ssl_cert').join}"
    describe "SSL Certificate file: #{full_cert_path}" do
      subject { file(full_cert_path) }
      it { should exist }
    end

    describe x509_certificate(full_cert_path) do
      its('issuer.CN') { should match org_approved_cert_issuer }
    end

  else
    impact 0.0
    describe 'Not applicable since these requirements are handled within AWS RDS' do
      skip 'Not applicable since these requirements are handled within AWS RDS'
    end
  end
end
