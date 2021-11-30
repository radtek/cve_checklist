SELECT decode(count(0),0,0,1)
FROM   dba_sys_privs
WHERE  privilege = 'CREATE PROCEDURE'
      AND grantee IN (SELECT username
                      FROM   dba_users
                      WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE',
                                              'SYSTEM_ACCOUNTS',
                                              'DEFAULT',
                                              'C##SYSTEM_ACCOUNTS',
                                              'C##DBS_SERVICES_PROFILE' ));

SELECT decode(count(0),0,0,1)
FROM   dba_users
WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE', 'SYSTEM_ACCOUNTS', 'DEFAULT',
                              'C##SYSTEM_ACCOUNTS',
                                             'C##DBS_SERVICES_PROFILE' )
      AND username IN (SELECT DISTINCT grantee
                       FROM   dba_role_privs
                       WHERE  granted_role IN (SELECT role
                                               FROM   role_sys_privs
                                               WHERE
                              privilege = 'CREATE PROCEDURE'));

SELECT decode(count(0),0,0,1)
FROM   dba_java_policy
WHERE  grantee IN (SELECT username
                  FROM   dba_users
                  WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE',
                                          'SYSTEM_ACCOUNTS',
                                          'DEFAULT',
                                          'C##SYSTEM_ACCOUNTS',
                                          'C##DBS_SERVICES_PROFILE' ));

SELECT  decode(count(0),0,0,1)
FROM   dba_java_policy
WHERE  grantee IN (SELECT username
                  FROM   dba_users
                  WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE',
                                          'SYSTEM_ACCOUNTS',
                                          'DEFAULT',
                                          'C##SYSTEM_ACCOUNTS',
                                          'C##DBS_SERVICES_PROFILE' ));

SELECT  decode(count(0),0,0,1)
FROM   dba_tab_privs
WHERE  grantee = 'PUBLIC'
      AND privilege = 'EXECUTE'
      AND table_name IN ( 'DBMS_JAVA', 'DBMS_JAVA_TEST' );

SELECT decode(count(0),0,0,1)
FROM   dba_role_privs
WHERE  granted_role IN ( 'JAVASYSPRIV', 'JAVADEBUGPRIV', 'JAVAUSERPRIV',
                        'JAVA_ADMIN',
                        'JAVA_DEPLOY', 'JAVAIDPRIV', 'DBJAVASCRIPT' )
      AND grantee IN (SELECT username
                      FROM   dba_users
                      WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE',
                                              'SYSTEM_ACCOUNTS',
                                              'DEFAULT',
                                              'C##SYSTEM_ACCOUNTS',
                                              'C##DBS_SERVICES_PROFILE' ));

SELECT  decode(count(0),0,0,1)
FROM   dba_java_policy
WHERE  type_name = 'java.io.FilePermission'
      AND action LIKE '%execute%'
      AND ( NAME = '<<ALL FILES>>'
             OR NAME LIKE '%*%' )
      AND kind = 'GRANT'
      AND enabled = 'ENABLED'
      AND grantee != 'JAVASYSPRIV';

SELECT  decode(count(0),0,0,1)
FROM   dba_java_policy
WHERE  type_name = 'java.security.AllPermission'
      AND kind = 'GRANT'
      AND enabled = 'ENABLED'
      AND grantee != 'SYS';

SELECT  decode(count(0),0,0,1)
FROM   dba_java_policy
WHERE  type_name = 'java.io.FilePermission'
      AND action LIKE '%write%'
      AND NAME = '<<ALL FILES>>'
      AND kind = 'GRANT'
      AND enabled = 'ENABLED'
      AND grantee != 'JAVASYSPRIV';

SELECT DISTINCT 'EXEC DBMS_JAVA.DELETE_PERMISSION('
               || seq
               || ');'
FROM   dba_java_policy
WHERE  type_name = 'java.lang.RuntimePermission'
      AND NAME LIKE '%loadLibrary%'
      AND kind = 'GRANT'
      AND enabled = 'ENABLED'
      AND grantee NOT IN ( 'SYS', 'ORDSYS' );

SELECT  decode(count(0),0,0,1)
FROM   dba_tab_privs
WHERE  table_name LIKE 'JAVA\$POLICY\$';
SELECT  decode(count(0),0,0,1)
FROM   DBA_ROLE_PRIVS
WHERE  granted_role = 'DBA'
       AND grantee IN (SELECT username
                       FROM   DBA_USERS
                       WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE',
                                               'SYSTEM_ACCOUNTS',
                                               'DEFAULT',
                                               'C##SYSTEM_ACCOUNTS',
                                               'C##DBS_SERVICES_PROFILE' ));

SELECT  decode(count(0),0,0,1)
FROM   DBA_PROXIES
WHERE  client IN (SELECT grantee
                  FROM   DBA_ROLE_PRIVS
                  WHERE  granted_role = 'DBA');
 SELECT   decode(count(0),0,0,1)
FROM   dba_tab_privs
WHERE  table_name LIKE '%V%LOGMNR%'
       AND grantee IN (SELECT username
                       FROM   dba_users
                       WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE',
                                               'SYSTEM_ACCOUNTS',
                                               'DEFAULT',
                                               'C##SYSTEM_ACCOUNTS',
                                               'C##DBS_SERVICES_PROFILE' ));
SELECT  decode(count(0),0,0,1)
FROM   dba_tab_privs
WHERE  privilege = 'EXECUTE'
       AND table_name LIKE '%V%LOGMNR%'
       AND grantee IN (SELECT username
                       FROM   dba_users
                       WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE',
                                               'SYSTEM_ACCOUNTS',
                                               'DEFAULT',
                                               'C##SYSTEM_ACCOUNTS',
                                               'C##DBS_SERVICES_PROFILE' ));
 SELECT   decode(count(0),0,0,1)
FROM   v$pwfile_users
WHERE  username NOT IN ('ANONYMOUS',
                        'APEX_050100',
                        'APEX_PUBLIC_USER',
                        'APPQOSSYS',
                        'AUDSYS',
                        'CTXSYS',
                        'DBSFWUSER',
                        'DBSNMP',
                        'DIP',
                        'DVSYS',
                        'DVF',
                        'FLOWS_FILES',
                        'GGSYS',
                        'GSMADMIN_INTERNAL',
                        'GSMATUSER',
                        'GSMUSER',
                        'HR',
                        'LBACSYS',
                        'MDDATA',
                        'MDSYS',
                        'OUTLN',
                        'ORACLE_OCM',
                        'REMOTE_SCHEDULER_AGENT',
                        'SYS',
                        'SYSTEM',
                        'SYSBACKUP',
                        'SYSKM',
                        'SYSDG',
                        'SYSRAC',
                        'SYS\$UMF',
                        'WMSYS',
                        'XDB',
                        'XS\$NULL');

SELECT   decode(count(0),0,0,1)
FROM   DBA_ROLE_PRIVS
WHERE  granted_role='DBA'
AND    grantee IN
                   (
                   SELECT DISTINCT username
                   FROM            DBA_USERS)
AND    grantee NOT IN ('SYS',
                       'SYSTEM');

SELECT   decode(count(0),0,0,1)
FROM   ROLE_ROLE_PRIVS
WHERE  granted_role = 'DBA';

SELECT   decode(count(0),0,0,1)
FROM   DBA_ROLE_PRIVS
WHERE  admin_option = 'YES'
AND    granted_role = 'DBA'
AND    grantee IN
                   (
                   SELECT DISTINCT username
                   FROM            DBA_USERS)
AND    grantee NOT IN ('SYS',
                       'SYSTEM');
SELECT   decode(count(0),0,0,1)
FROM   ROLE_ROLE_PRIVS
WHERE  admin_option = 'YES'
AND    granted_role = 'DBA' ;


SELECT   decode(count(0),0,0,1)
FROM   DBA_SYS_PRIVS
WHERE  privilege = 'CREATE TABLE'
AND    grantee IN
       (
              SELECT username
              FROM   DBA_USERS
              WHERE  profile NOT IN ('DBS_SERVICES_PROFILE',
                                     'SYSTEM_ACCOUNTS',
                                     'DEFAULT',
                                     'C##SYSTEM_ACCOUNTS',
                                     'C##DBS_SERVICES_PROFILE'));
 SELECT   decode(count(0),0,0,1)
FROM   DBA_SYS_PRIVS
WHERE  privilege = 'UNLIMITED TABLESPACE'
       AND grantee IN (SELECT username
                       FROM   DBA_USERS
                       WHERE  profile NOT IN ( 'DBS_SERVICES_PROFILE',
                                               'SYSTEM_ACCOUNTS',
                                               'DEFAULT',
                                               'C##SYSTEM_ACCOUNTS',
                                               'C##DBS_SERVICES_PROFILE' ));
