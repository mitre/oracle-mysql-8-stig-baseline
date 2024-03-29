control 'SV-235137' do
  title "If Database Management System (DBMS) authentication using passwords is
employed, the DBMS must enforce the #{input('org_name')} standards for password complexity and
lifetime."
  desc  "OS/enterprise authentication and identification must be used
(SRG-APP-000023-DB-000001). Native DBMS authentication may be used only when
circumstances make it unavoidable; and must be documented and Authorizing
Official (AO)-approved.

    The #{input('org_name')} standard for authentication is #{input('org_name')}-approved PKI certificates.
Authentication based on User ID and Password may be used only when it is not
possible to employ a PKI certificate, and requires AO approval.

    In such cases, the #{input('org_name')} standards for password complexity and lifetime must
be implemented. DBMS products that can inherit the rules for these from the
operating system or access control program (e.g., Microsoft Active Directory)
must be configured to do so.  For other DBMSs, the rules must be enforced using
available configuration parameters or custom code.
  "
  desc  'rationale', ''
  desc  'check', "
    If DBMS authentication using passwords is not employed, this is not a
finding.

    If the DBMS is configured to inherit password complexity and lifetime rules
from the operating system or access control program, this is not a finding.

    Review the MySQL Database Server 8.0 settings relating to password
complexity. Determine whether the following rules are enforced. If any are not,
this is a finding.
    a. minimum of #{input('min_password_length')} characters, including at least one of each of the
following character sets:
    - Uppercase
    - Lowercase
    - Numeric
    - Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
    b. Minimum number of characters changed from previous password: 50 percent
of the minimum password length; that is, eight

    Review the DBMS settings relating to password lifetime. Determine whether
the following rules are enforced. If any are not, this is a finding.
    a. Password lifetime limits for interactive accounts: Minimum 24 hours,
maximum 60 days
    b. Password lifetime limits for non-interactive accounts: Minimum 24 hours,
maximum 365 days
    c. Number of password changes before an old one may be reused: Minimum of
five

    Connect as an admin.

    SELECT component_urn FROM mysql.component
    where component_urn='file://component_validate_password' group by
component_urn;

    If the \"validate password\" component is installed the result will be
file://component_validate_password.

    If \"validate password\" component is not installed, this is a finding.

    If the \"component_validate_password\" is installed, review the password
policies to ensure required password complexity is met.

*** On AWS RDS:
    SELECT plugin_name, plugin_status, plugin_type, plugin_library FROM 
    information_schema.plugins WHERE plugin_name='validate_password';
    If the \"validate_password\" password plugin is installed its status will be \"ACTIVE\".
    If the \"validate_password\" password plugin is not installed, this is a finding.
    If the \"validate_password\" password plugin is installed, review the password
    policies to ensure required password complexity is met.
***

    Run the following to review the password policy:
    SELECT VARIABLE_NAME, VARIABLE_VALUE
    FROM performance_schema.global_variables where VARIABLE_NAME like
'valid%password%' or VARIABLE_NAME like 'password_%'  ;

    For example the results may look like the following:
    'validate_password.check_user_name',’ON’    # On AWS RDS the variable name is: 'validate_password_check_user_name', but it is OFF and cannot be configured
    'validate_password.dictionary_file',''      # On AWS RDS the variable name is: 'validate_password_dictionary_file', but has no dictionary and cannot be configured
    'validate_password.length','8'              # On AWS RDS the variable name is: 'validate_password_length'
    'validate_password.mixed_case_count','1'    # On AWS RDS the variable name is: 'validate_password_mixed_case_count'
    'validate_password.number_count','1'        # On AWS RDS the variable name is: 'validate_password_number_count'
    'validate_password.policy','MEDIUM'         # On AWS RDS the variable name is: 'validate_password_policy'
    'validate_password.special_char_count','1'  # On AWS RDS the variable name is: 'validate_password_special_char_count'
    'password_reuse_interval','0'
    'password_require_current','OFF'
    'password_history','0'

    If these results do not meet password complexity requirements listed above,
this is a finding.
  "
  desc 'fix', "
    If the use of passwords is not needed, configure the MySQL Database Server
8.0 to prevent their use if it is capable of this; if it is not so capable,
institute policies and procedures to prohibit their use.

    If the MySQL Database Server 8.0 can inherit password complexity rules from
the operating system or access control program, configure it to do so.

    Otherwise, use MySQL Database Server 8.0 configuration parameters and/or
custom code to enforce the following rules for passwords:

    a. minimum of #{input('min_password_length')} characters, including at least one of each of the
following character sets:
    - Uppercase
    - Lowercase
    - Numeric
    - Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
    b. Minimum number of characters changed from previous password: 50 percent
of the minimum password length; that is, eight
    c. Password lifetime limits for interactive accounts: Minimum 24 hours,
maximum 60 days
    d. Password lifetime limits for non-interactive accounts: Minimum 24 hours,
maximum 365 days
    e. Number of password changes before an old one may be reused: Minimum of
five

    As the database admin:

    INSTALL COMPONENT 'file://component_validate_password';

    # Set Password Policies - For Example
    set persist validate_password.check_user_name='ON';
    set persist validate_password.dictionary_file='<FILENAME OF DICTIONARY FILE>';
    set persist validate_password.length=15;            # On AWS RDS the variable name is: 'validate_password_length'
    set persist validate_password.mixed_case_count=1;   # On AWS RDS the variable name is: 'validate_password_mixed_case_count'
    set persist validate_password.special_char_count=2; # On AWS RDS the variable name is: 'validate_password_special_char_count'
    set persist validate_password.number_count=2;       # On AWS RDS the variable name is: 'validate_password_number_count'
    set persist validate_password.policy='STRONG';      # On AWS RDS the variable name is: 'validate_password_policy'
    set persist password_history = 5;
    set persist password_reuse_interval = 365;
    SET GLOBAL default_password_lifetime = 180;

    Optional
    set persist password_require_current=YES

    This can also be set at the account level:
    ALTER USER 'jeffrey'@'localhost'
      PASSWORD HISTORY 5
      PASSWORD REUSE INTERVAL 365 DAY;
    ALTER USER 'jeffrey'@'localhost' PASSWORD EXPIRE INTERVAL 90 DAY;
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag gid: 'V-235137'
  tag rid: 'SV-235137r638812_rule'
  tag stig_id: 'MYS8-00-005000'
  tag fix_id: 'F-38319r623532_fix'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  query_password_params = %(
  SELECT variable_name,
         variable_value
  FROM   performance_schema.global_variables
  WHERE  variable_name LIKE 'valid%password%'
          OR variable_name LIKE 'password_%'
          OR variable_name LIKE 'default_password_lifetime'; 
  )

  password_params = sql_session.query(query_password_params).results.rows.map{|x| {x['variable_name']=> x['variable_value']}}.reduce({}, :merge)

	if !input('aws_rds')
  
		query_component = %(
		SELECT component_urn
		FROM   mysql.component
		GROUP  BY component_urn; 
		)

		describe "List of installed components" do
			subject { sql_session.query(query_component).results.column('component_urn') }
			it { should include 'file://component_validate_password' }
		end

		describe "Password requirement:" do
			subject { password_params }
			its(['validate_password.check_user_name']) { should cmp 'ON' }
			its(['validate_password.length']) { should cmp >= input('min_password_length') }
			its(['validate_password.mixed_case_count']) { should cmp >= input('password_mixed_case_count') }
			its(['validate_password.special_char_count']) { should cmp >= input('password_special_character_count') }
			its(['validate_password.number_count']) { should cmp >= input('password_number_count') }
			its(['validate_password.policy']) { should cmp 'STRONG' }
			its(['password_history']) { should cmp >= input('password_history') }
			its(['password_reuse_interval']) { should cmp >= 365 }
			its(['default_password_lifetime']) { should cmp >= input('max_password_lifetime') }
		end

	else

		query_component = %(
    SELECT plugin_name, plugin_status, plugin_type, plugin_library
		FROM information_schema.plugins
		WHERE plugin_name='validate_password';
    )

    describe "Validate_password Plugin Status" do
      subject { sql_session.query(query_component).results.column('plugin_status') }
      it { should cmp 'ACTIVE' }
    end

		describe "Password requirement:" do
      subject { password_params }
      its(['validate_password_length']) { should cmp >= input('min_password_length') }
      its(['validate_password_mixed_case_count']) { should cmp >= input('password_mixed_case_count') }
      its(['validate_password_special_char_count']) { should cmp >= input('password_special_character_count') }
      its(['validate_password_number_count']) { should cmp >= input('password_number_count') }
      its(['validate_password_policy']) { should cmp 'STRONG' }
      its(['password_history']) { should cmp >= input('password_history') }
      its(['password_reuse_interval']) { should cmp >= 365 }
      its(['default_password_lifetime']) { should cmp >= input('max_password_lifetime') }
    end
	end
end
