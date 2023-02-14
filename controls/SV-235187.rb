control 'SV-235187' do
  title "The MySQL Database Server 8.0 must use NSA-approved cryptography to
protect classified information in accordance with the data owner's
requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The application must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated.

    It is the responsibility of the data owner to assess the cryptography
requirements in light of applicable federal laws, Executive Orders, directives,
policies, regulations, and standards.

    NSA-approved cryptography for classified networks is hardware based. This
requirement addresses the compatibility of a DBMS with the encryption devices.
  "
  desc  'rationale', ''
  desc  'check', "
    Detailed information on the NIST Cryptographic Module Validation Program
(CMVP) is available at the following website:
http://csrc.nist.gov/groups/STM/cmvp/index.html.

    Review system documentation to determine whether cryptography for
classified or sensitive information is required by the information owner.

    If the system documentation does not specify the type of information hosted
on MySQL: classified, sensitive, and/or unclassified, this is a finding.

    If classified or sensitive information does not exist within MySQL Server,
this is not a finding.

    Verify that the operating system provides the OpenSSL FIPS Object Module,
and is configured to require the use of OpenSSL of FIPS compliant algorithms,
available at MySQL runtime.

    If the Security Setting for FIPS mode option is \"Disabled\" on the
server's OS, this is a finding.

    If cryptography is being used by MySQL, verify that the cryptography is
NIST FIPS 140-2 certified by running the following SQL query:
    Determine if MySQL is running in FIPS mode.
    select @@ssl_fips_mode;

    If ssl_fips_mode is not \"ON\" or \"STRICT\", this is a finding.

    View the versions of TLS, then review the cipher suites in use for the
versions returned by statement:
    SELECT VARIABLE_NAME, VARIABLE_VALUE
    FROM performance_schema.global_variables WHERE VARIABLE_NAME =
'tls_version';

    If the results include less than version TLS 1.2, for example TLS 1.0 or
1.1, this is a finding.

    If the results include TLS 1.2 view the supported ciphers on the MySQL
Server, run
    select * from performance_schema.global_status where variable_name=
'Ssl_cipher_list';

    If the results include TLS 1.3 view the supported ciphers on the MySQL
Server, run
    SELECT VARIABLE_NAME, VARIABLE_VALUE
    FROM performance_schema.global_variables WHERE VARIABLE_NAME =
'tls_ciphersuites';

    If any results list show an uncertified NIST FIPS 140-2 algorithm type,
this is a finding.

    Check MySQL certificate PEM file(s) for compliance with #{input('org_name')} requirements by
running this command:
    openssl x509 -in server-cert.pem -text -noout

    If any PEM file is not in compliance, this is a finding.
  "
  desc 'fix', "
    Configure cryptographic functions to use NSA-approved
cryptography-compliant algorithms.

    Turn on MySQL FIPS mode.
    Edit my.cnf
    [mysqld]
    ssl_fips_mode=ON

    or
    [mysqld]
    ssl_fips_mode=STRICT

    To restrict TLS versions:

     [mysqld]
     tls_version='TLSv1.2,TLSv1.3'

     Example to define ciphers for TLSv1.2:

     [mysqld]

ssl_ciphers='ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384,DHE-RSA-AES128-GCM-SHA256,DHE-DSS-AES128-GCM-SHA256,DHE-DSS-AES256-GCM-SHA384,DHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-RSA-CHACHA20-POLY1305'

    If TLSv1.3 is enabled, the \"tls_ciphersuites\" setting must contain all or
a subset of following ciphers based on certificates being used by server and
client. Enabling FIPS mode will limit the OpenSSL library to operate within the
FIPS object module.

     Example to define TLS ciphers for TLSv1.3:

     [mysqld]

tls_ciphersuites='TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_CCM_SHA256,TLS_AES_128_CCM_8_SHA256'

    After adding any entries to the my.cnf file, restart mysqld.

    Create and use #{input('org_name')}-approved certificates for asymmetric keys used by the
database.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000416-DB-000380'
  tag gid: 'V-235187'
  tag rid: 'SV-235187r638812_rule'
  tag stig_id: 'MYS8-00-011500'
  tag fix_id: 'F-38369r623682_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  query_ssl_params = %(
  SELECT @@ssl_fips_mode,
         @@datadir,
         @@ssl_cert,
         @@tls_version;
  )

  ssl_params = sql_session.query(query_ssl_params).results

  describe '@@ssl_fips_mode' do
    subject { ssl_params.column('@@ssl_fips_mode').join }
    it { should match /1|ON/ }
  end

  describe '@@tls_version' do
    subject { ssl_params.column('@@tls_version').join.split(',') }
    it { should_not be_empty }
    it { should_not include 'TLSv1' }
    it { should_not include 'TLSv1.1' }
  end

  query_ssl_cipher_list = %(
  SELECT
     * 
  FROM
     performance_schema.global_status 
  WHERE
     variable_name = 'Ssl_cipher_list';
  )

  approved_ssl_cipher_list = %w(
    ECDHE-ECDSA-AES128-GCM-SHA256
    ECDHE-ECDSA-AES256-GCM-SHA384
    ECDHE-RSA-AES128-GCM-SHA256
    ECDHE-RSA-AES256-GCM-SHA384
    DHE-RSA-AES128-GCM-SHA256
    DHE-DSS-AES128-GCM-SHA256
    DHE-DSS-AES256-GCM-SHA384
    DHE-RSA-AES256-GCM-SHA384
    ECDHE-ECDSA-CHACHA20-POLY1305
    ECDHE-RSA-CHACHA20-POLY1305
  )

  ssl_cipher_list = sql_session.query(query_ssl_cipher_list).results
  
  describe 'Ssl_cipher_list' do
    subject { ssl_cipher_list.column('variable_value').join.split(',') }
    it { should_not be_empty }
    it { should be_in approved_ssl_cipher_list }
  end

  query_tls_ciphersuites = %(
  SELECT
     VARIABLE_NAME,
     VARIABLE_VALUE 
  FROM
     performance_schema.global_variables 
  WHERE
     VARIABLE_NAME = 'tls_ciphersuites';
  )

  approved_tls_ciphersuites = %w(
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_AES_128_CCM_8_SHA256
  )

  tls_ciphersuite_list = sql_session.query(query_tls_ciphersuites).results
  
  describe 'tls_ciphersuites' do
    subject { tls_ciphersuite_list.column('variable_value').join.split(',') }
    it { should_not be_empty }
    it { should be_in approved_tls_ciphersuites }
  end

  dod_appoved_cert_issuer = input('dod_appoved_cert_issuer')

  full_cert_path = "#{ssl_params.column('@@datadir').join}#{ssl_params.column('@@ssl_cert').join}"
  describe "SSL Certificate file: #{full_cert_path}" do
    subject { file(full_cert_path) }
    it { should exist }
  end

  describe x509_certificate(full_cert_path) do
    its('issuer.CN') { should match dod_appoved_cert_issuer}
  end
end
