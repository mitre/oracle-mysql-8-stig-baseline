USE mysql;

CREATE TABLE IF NOT EXISTS audit_log_filter(NAME VARCHAR(64) BINARY NOT NULL PRIMARY KEY, FILTER JSON NOT NULL) engine= InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_ci;
CREATE TABLE IF NOT EXISTS audit_log_user(USER VARCHAR(32) BINARY NOT NULL, HOST VARCHAR(60) BINARY NOT NULL, FILTERNAME VARCHAR(64) BINARY NOT NULL, PRIMARY KEY (USER, HOST), FOREIGN KEY (FILTERNAME) REFERENCES mysql.audit_log_filter(NAME)) engine= InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_ci;

CREATE FUNCTION audit_log_filter_set_filter RETURNS STRING SONAME 'audit_log.so';
CREATE FUNCTION audit_log_filter_remove_filter RETURNS STRING SONAME 'audit_log.so';
CREATE FUNCTION audit_log_filter_set_user RETURNS STRING SONAME 'audit_log.so';
CREATE FUNCTION audit_log_filter_remove_user RETURNS STRING SONAME 'audit_log.so';
CREATE FUNCTION audit_log_filter_flush RETURNS STRING SONAME 'audit_log.so';
CREATE FUNCTION audit_log_read_bookmark RETURNS STRING SONAME 'audit_log.so';
CREATE FUNCTION audit_log_read RETURNS STRING SONAME 'audit_log.so';
CREATE FUNCTION audit_log_encryption_password_set RETURNS INTEGER SONAME 'audit_log.so';
CREATE FUNCTION audit_log_encryption_password_get RETURNS STRING SONAME 'audit_log.so';

SELECT audit_log_filter_flush() AS 'Result';

SET @log_all ='{ "filter": { "log": true } }';
SELECT audit_log_filter_set_filter('log_all',@log_all);
SELECT audit_log_filter_set_user('%','log_all');

SET PERSIST max_user_connections=50;
INSTALL COMPONENT 'file://component_validate_password';

set persist require_secure_transport=ON;

# Set Password Policies - For Example
set persist validate_password.check_user_name='ON';
set persist validate_password.length=15;
set persist validate_password.mixed_case_count=1;
set persist validate_password.special_char_count=2;
set persist validate_password.number_count=2;
set persist validate_password.policy='STRONG';
set persist password_history = 5;
set persist password_reuse_interval = 365;
SET GLOBAL default_password_lifetime = 180;

CALL mysql.sp_set_firewall_mode('fwuser@localhost', 'DETECTING');
 
#Turn on binlog encryption
-- set persist binlog_encryption=ON;

#Turn on undo and redo log encryption
set persist innodb_redo_log_encrypt=ON;
set persist innodb_undo_log_encrypt=ON;

SET GLOBAL innodb_file_per_table=ON;