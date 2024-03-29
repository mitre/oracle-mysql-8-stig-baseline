control 'SV-235139' do
  title "If passwords are used for authentication, the MySQL Database Server
8.0 must transmit only encrypted representations of passwords."
  desc  "The #{input('org_name')} standard for authentication is #{input('org_name')}-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is
not possible to employ a PKI certificate, and requires Authorizing Official
(AO) approval.

    In such cases, passwords need to be protected at all times, and encryption
is the standard method for protecting passwords during transmission.

    Database Management System (DBMS) passwords sent in clear text format
across the network are vulnerable to discovery by unauthorized users.
Disclosure of passwords may easily lead to unauthorized access to the database.
  "
  desc  'rationale', ''
  desc  'check', "
    Review configuration settings for encrypting passwords in transit across
the network. If passwords are not encrypted, this is a finding.

    If it is determined that passwords are passed unencrypted at any point
along the transmission path between the source and destination, this is a
finding.

    To check, run the following SQL:
    SELECT VARIABLE_NAME, VARIABLE_VALUE
    FROM performance_schema.global_variables
    WHERE VARIABLE_NAME IN ('require_secure_transport') ;
    If the require_secure_transport VARIABLE_VALUE is not  'ON' (1), this is a
finding.

     If 1 (On), then only SSL connections are permitted; next examine the
certificate used.

    Run the following command to determine the certificate in use along with
other details:
    select @@ssl_ca, @@ssl_capath, @@ssl_cert, @@ssl_cipher, @@ssl_crl,
@@ssl_crlpath, @@ssl_fips_mode, @@ssl_key;

    If the certificate is not a #{input('org_name')} certificate, or if no certificate is
listed, this is a finding.
  "
  desc 'fix', "
    Configure encryption for transmission of passwords across the network. If
the database does not provide encryption for logon events natively, employ
encryption at the OS or network level.

    Ensure passwords remain encrypted from source to destination.

    connect to MySQL as admin (root)
    mysql> set persist require_secure_transport=ON;

    Set system variables on the server side specify  #{input('org_name')} approved certificate
and key files the server uses when permitting clients to establish encrypted
connections:

    ssl_ca: The path name of the Certificate Authority (CA) certificate file.
(ssl_capath is similar but specifies the path name of a directory of CA
certificate files.)

    ssl_cert: The path name of the server public key certificate file. This
certificate can be sent to the client and authenticated against the CA
certificate that it has.

    ssl_key: The path name of the server private key file.

    For example, to enable the server for encrypted connections with
certificates, start it with these lines in the my.cnf file, changing the file
names as necessary:

    [mysqld]
    ssl_ca=ca.pem
    ssl_cert=server-cert.pem
    ssl_key=server-key.pem
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag gid: 'V-235139'
  tag rid: 'SV-235139r638812_rule'
  tag stig_id: 'MYS8-00-005200'
  tag fix_id: 'F-38321r623538_fix'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  org_approved_cert_issuer = input('org_approved_cert_issuer')

  query_ssl_params = %(
  SELECT @@ssl_ca,
         @@ssl_capath,
         @@ssl_cert,
         @@ssl_cipher,
         @@ssl_crl,
         @@ssl_crlpath,
         @@ssl_fips_mode,
         @@ssl_key,
         @@require_secure_transport,
         @@datadir;
  )

  ssl_params = sql_session.query(query_ssl_params).results

  require_secure_transport = ssl_params.column('@@require_secure_transport').join
  describe '@@require_secure_transport' do
    it "should be 1 or ON. Got #{require_secure_transport}" do
      expect(require_secure_transport).to be_in(['1', 'ON'])
    end
  end

  if !input('aws_rds')
    full_cert_path = "#{ssl_params.column('@@datadir').join}#{ssl_params.column('@@ssl_cert').join}"
    describe "SSL Certificate file: #{full_cert_path}" do
        subject { file(full_cert_path) }
        it { should exist }
    end

    describe x509_certificate(full_cert_path) do
        its('issuer.CN') { should match org_approved_cert_issuer}
    end
	end
end
