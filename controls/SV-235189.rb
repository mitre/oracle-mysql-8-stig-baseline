control 'SV-235189' do
  title "The MySQL Database Server 8.0 must implement NIST FIPS 140-2 validated
cryptographic modules to generate and validate cryptographic hashes."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The application must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated.

    For detailed information, refer to NIST FIPS Publication 140-2, Security
Requirements For Cryptographic Modules. Note that the product's cryptographic
modules must be validated and certified by NIST as FIPS-compliant.
  "
  desc  'rationale', ''
  desc  'check', "
    ALL cryptography is provided via OpenSSL and can be verified in FIPS mode.

    Run this command:
    SELECT VARIABLE_NAME, VARIABLE_VALUE
    FROM performance_schema.global_variables where variable_name =
'ssl_fips_mode';

    If the VARIABLE_VALUE does not return \"ON\" or \"STRICT\", this is a
finding.

    In general, STRICT imposes more restrictions than ON, but MySQL itself has
no FIPS-specific code other than to specify to OpenSSL the FIPS mode value. The
exact behavior of FIPS mode for ON or STRICT depends on the OpenSSL version.
  "
  desc 'fix', "
    Implement NIST FIPS 140-2 validated cryptographic modules to provision
digital signatures.

    Turn on MySQL FIPS mode and restart mysqld
    Edit my.cnf
    [mysqld]
    ssl_fips_mode=ON

    or
    [mysqld]
    ssl_fips_mode=STRICT

    In general, STRICT imposes more restrictions than ON, but MySQL itself has
no FIPS-specific code other than to specify to OpenSSL the FIPS mode value. The
exact behavior of FIPS mode for ON or STRICT depends on the OpenSSL version.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000514-DB-000382'
  tag gid: 'V-235189'
  tag rid: 'SV-235189r638812_rule'
  tag stig_id: 'MYS8-00-011700'
  tag fix_id: 'F-38371r623688_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  query_ssl_params = %(
  SELECT @@ssl_fips_mode;
  )

  ssl_params = sql_session.query(query_ssl_params).results

  if !input('aws_rds')

    ssl_fips_mode = ssl_params.column('@@ssl_fips_mode').join
    describe '@@ssl_fips_mode' do
      it "should be 1 or ON. Got #{ssl_fips_mode}" do
        expect(ssl_fips_mode).to be_in(['1', 'ON'])
      end
    end
    
  else
    
    impact 0.0
    describe 'Not applicable since ssl_fips_mode is set to 0 (OFF) and cannot be configured in AWS RDS' do
      skip 'Not applicable since ssl_fips_mode is set to 0 (OFF) and cannot be configured in AWS RDS'
    end
    
  end    
    
end
