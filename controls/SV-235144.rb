control 'SV-235144' do
  title "Unused database components, MySQL Database Server 8.0 software, and
database objects must be removed."
  desc  "Information systems are capable of providing a wide variety of
functions and services. Some of the functions and services, provided by
default, may not be necessary to support essential organizational operations
(e.g., key missions, functions).

    It is detrimental for software products to provide, or install by default,
functionality exceeding requirements or mission objectives.

    Database Management Systems (DBMSs) must adhere to the principles of least
functionality by providing only essential capabilities.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the list of components and features installed with the MySQL
Database Server 8.0.

    List options MySQL Plugins/Components

    SELECT * FROM information_schema.PLUGINS where plugin_library is NOT NULL;

    Compare the feature listing against the required plugins listing.

    If any plugins are installed, but are not required, this is a finding.

    SELECT * FROM mysql.component;

    Compare the feature listing against the required components listing.

    If any components are installed, but are not required, this is a finding.
  "
  desc 'fix', "
    Uninstall unused components or features that are installed and can be
uninstalled. Remove any database objects and applications that are installed to
support them.

    After review of installed plugin components uninstall unused plugins. To do
this while the server is running using the UNINSTALL PLUGIN; command:

    Remove any plugin that is loaded at startup from the my.cnf file.

    For example - ddl_rewriter is discovered but are not being used. Follow
these removal instructions.
    Remove this line from my.cnf:
    plugin-load-add=ddl_rewriter.so

    Remove any plugin that is not loaded at startup using the --plugin-load
parameter from the my.cnf or on the command line.
    UNINSTALL PLUGIN <plugin_name>;
    UNINSTALL PLUGIN ddl_rewriter;

    Remove any component not in use
    UNINSTALL COMPONENT component_name [, component_name ] ...;

    For example - The audit message emit function is not being called, the
component is not needed.
    UNINSTALL COMPONENT \"file://component_audit_api_message_emit\";
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag gid: 'V-235144'
  tag rid: 'SV-235144r638812_rule'
  tag stig_id: 'MYS8-00-005700'
  tag fix_id: 'F-38326r623553_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  approved_plugins = input('approved_plugins')
  approved_components = input('approved_components')

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  if !input('aws_rds')
   approved_plugins = input('approved_plugins')
  else
   approved_plugins = input('approved_plugins') + ['validate_password','RDS_PROCESSLIST','RDS_EVENTS_THREADS_WAITS_CURRENT']
  end

  query_plugins = %(
  SELECT
     * 
  FROM
     information_schema.PLUGINS 
  where
     plugin_library is NOT NULL;
  )

  describe 'Installed plugins' do
    subject { sql_session.query(query_plugins).results.column('plugin_name') }
    it { should be_in approved_plugins }
  end

	if !input('aws_rds')
    query_components = %(
    SELECT
      * 
    FROM
      mysql.component;
    )

    describe 'Installed components' do
      subject { sql_session.query(query_components).results.column('component_urn') }
      it { should be_in approved_components }
    end
  end
end
