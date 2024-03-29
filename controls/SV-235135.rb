control 'SV-235135' do
  title "The MySQL Database Server 8.0 must enforce authorized access to all
PKI private keys stored/utilized by the MySQL Database Server 8.0."
  desc  "The #{input('org_name')} standard for authentication is #{input('org_name')}-approved PKI certificates.
PKI certificate-based authentication is performed by requiring the certificate
holder to cryptographically prove possession of the corresponding private key.

    If the private key is stolen, an attacker can use it to impersonate the
certificate holder. In cases where the Database Management System (DBMS)-stored
private keys are used to authenticate the DBMS to the system's clients, loss of
the corresponding private keys would allow an attacker to successfully perform
undetected man-in-the-middle attacks against the DBMS system and its clients.

    Both the holder of a digital certificate, and the issuing authority, must
take careful measures to protect the corresponding private key. Private keys
must always be generated and protected in FIPS 140-2 validated cryptographic
modules.

    All access to the private key(s) of the DBMS must be restricted to
authorized and authenticated users. If unauthorized users have access to one or
more of the DBMS's private keys, an attacker could gain access to the key(s)
and use them to impersonate the database on the network or otherwise perform
unauthorized actions.
  "
  desc  'rationale', ''
  desc  'check', "
    Review DBMS configuration to determine whether appropriate access controls
exist to protect the DBMS’s private key.

    If strong access controls do not exist to enforce authorized access to the
private key, this is a finding.

    MySQL stores certificates in PEM formatted files.

    Verify User ownership, Group ownership, and permissions on the ssl_files.

    select @@ssl_ca, @@ssl_capath, @@ssl_cert, @@ssl_cipher, @@ssl_crl,
@@ssl_crlpath, @@ssl_fips_mode, @@ssl_key;
    If ssl_path or ssl_crlpath are not defined the locations default to the
datadir.
    To determine the datadir
    select @@datadir;

    Example if path is  <directory where audit log files are located>/

    sudo sh -c 'ls -l  <directory where data files are located>/*.pem'
    For example if the value returned by \"select @@datadir;' is
/usr/local/mysql/data/
    sudo sh -c 'ls -l   /usr/local/mysql/data/*.pem'

    Password:
    -rw-------  1 _mysql  _mysql  1676 Feb 25 11:09  <directory where audit log
files are located>/ca-key.pem
    -rw-r--r--  1 _mysql  _mysql  1112 Feb 25 11:09  <directory where audit log
files are located>/ca.pem
    -rw-r--r--  1 _mysql  _mysql  1112 Feb 25 11:09  <directory where audit log
files are located>/client-cert.pem
    -rw-------  1 _mysql  _mysql  1680 Feb 25 11:09  <directory where audit log
files are located>/client-key.pem
    -rw-------  1 _mysql  _mysql  1676 Feb 25 11:09  <directory where audit log
files are located>/private_key.pem
    -rw-r--r--  1 _mysql  _mysql   452 Feb 25 11:09  <directory where audit log
files are located>/public_key.pem
    -rw-r--r--  1 _mysql  _mysql  1112 Feb 25 11:09  <directory where audit log
files are located>/server-cert.pem
    -rw-------  1 _mysql  _mysql  1680 Feb 25 11:09  <directory where audit log
files are located>/server-key.pem

    If the User owner is not \"mysql\", this is a finding.

    If the Group owner is not \"mysql\", this is a finding.

    For public certs and keys, permissions should be \"rw\" for mysql and
\"readonly\" for mysql group and world. These files by default are named
\"ca.pem\", \"client-cert.pem\", \"public_key.pem\", and \"server-cert.pem\".
If not, this is a finding.

    For private certs and keys, permissions should be \"rw\" for mysql and \"no
rights\" for mysql group or world. These files by default are named
\"ca-key.pem\", \"client-key.pem\", \"private_key.pem\", and
\"server-key.pem\". If not, this is a finding.

    Review system configuration to determine whether FIPS 140-2 support has
been enabled.

    select @@ssl_fips_mode;

    - OFF: Disable FIPS mode.
    - ON: Enable FIPS mode.
    - STRICT: Enable “strict” FIPS mode.

    If FIPS mode is not \"ON\" or \"STRICT\", this is a finding.

    If the server-key.pem has a password, verify when starting mysqld in a
console there is prompt requiring the passphrase for the server-key.
  "
  desc 'fix', "
    Implement strong access and authentication controls to protect the
database’s private key.

    Configure the database to support Transport Layer Security (TLS) protocols
and the put in place file systems permissions on authentication and signing
credentials, including private keys.

    Put keys in place in the datadir, or define their locations using
ssl_capath and ssl_crlpath.

    Ensure proper permissions are set to protect the private keys and
certificates.

    Change directory ssl_capath, ssl_crlpath, or the default datadir path.

    To determine the file paths:
    select @@ssl_capath, @@ssl_crlpath, @@ssl_key, @@datadir;

    Ensure OS account mysql owns all the pem and key files.
    $ chown mysql *.pem
    $ chgrp mysql *.key
    $ chmod 600 *.key\"
    $ chmod 600 *.pem

    Optionally, allow access to public keys.
    $ chmod 644 client-cert.pem client-key.pem
    $chmod 644 public_key.pem server-cert.pem

    If the server-key.pem has a password, provide this password when prompted
during a console startup. The server will not start without this password if
the server key is password protected.

    Edit the mysql configuration file.

    [mysqld]
    ssl-fips-mode=ON

    If the OpenSSL FIPS Object Module is not available, ssl_fips_mode to ON or
STRICT at startup causes the server to produce an error message and exit.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag gid: 'V-235135'
  tag rid: 'SV-235135r638812_rule'
  tag stig_id: 'MYS8-00-004800'
  tag fix_id: 'F-38317r623526_fix'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  query_ssl_params = %(
  SELECT @@ssl_ca,
         @@ssl_capath,
         @@ssl_cert,
         @@ssl_crl,
         @@ssl_crlpath,
         @@ssl_fips_mode,
         @@ssl_key,
         @@datadir;
  )

  ssl_params = sql_session.query(query_ssl_params).results

  if !input('aws_rds')

    ssl_fips_mode = ssl_params.column('@@ssl_fips_mode').join
    describe '@@ssl_fips_mode' do
      it "shoud be ON or STRICT. Got #{ssl_fips_mode}" do
        expect(ssl_fips_mode).to be_in(['ON', 'STRICT'])
      end
    end

    if ssl_params.column('@@ssl_crlpath').join.eql?('NULL')
      crl_path = ssl_params.column('@@datadir').join
    else
      crl_path = ssl_params.column('@@ssl_crlpath').join
    end

    full_crl_path = "#{crl_path}#{ssl_params.column('@@ssl_crl').join}"
    describe "SSL CRL file: #{full_crl_path}" do
      subject { file(full_crl_path) }
      it { should exist }
      its('owner') { should cmp 'mysql' }
      its('group') { should cmp 'mysql' }
      it { should_not be_more_permissive_than('0600') }
    end

    if ssl_params.column('@@ssl_capath').join.eql?('NULL')
      ca_path = ssl_params.column('@@datadir').join
    else
      ca_path = ssl_params.column('@@ssl_capath').join
    end

    full_ca_path = "#{ca_path}#{ssl_params.column('@@ssl_ca').join}"
    describe "SSL CA file: #{full_ca_path}" do
      subject { file(full_ca_path) }
      it { should exist }
      its('owner') { should cmp 'mysql' }
      its('group') { should cmp 'mysql' }
      it { should_not be_more_permissive_than('0644') }
    end

    full_cert_path = "#{ssl_params.column('@@datadir').join}#{ssl_params.column('@@ssl_cert').join}"
    describe "SSL Certificate file: #{full_cert_path}" do
      subject { file(full_cert_path) }
      it { should exist }
      its('owner') { should cmp 'mysql' }
      its('group') { should cmp 'mysql' }
      it { should_not be_more_permissive_than('0644') }
    end

    full_key_path = "#{ssl_params.column('@@datadir').join}#{ssl_params.column('@@ssl_key').join}"
    describe "SSL Private Key file: #{full_key_path}" do
      subject { file(full_key_path) }
      its('owner') { should cmp 'mysql' }
      its('group') { should cmp 'mysql' }
      it { should_not be_more_permissive_than('0600') }
    end
  else
    impact 0.0
    describe 'Not applicable since ssl_fips_mode is set to 0 (OFF) and cannot be configured in AWS RDS' do
      skip 'Not applicable since ssl_fips_mode is set to 0 (OFF) and cannot be configured in AWS RDS'
    end
  end
end
