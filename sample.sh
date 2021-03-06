#!/usr/bin/bash
#. ./oracle_param.ini
################################################################################
#                              CVE-2021-2333                                   
#                         12.1.0.2, 12.2.0.1, 19c                              
# Sample script that checks the DB version and execute a check following       
# by recommendation. 
# Create oracle_param.ini file with defined variables                                                         
# Both script and ini required to have u+x permission
# Sample exection
# $./sample.sh
# 
# Change History                                                               
# 15/10/2021  Deepak Baranwal  Original code. This is a template for creating     
#                              new Bash shell scripts.                            
#                              Add new history entries as needed.                 
#                                                                              
#                                                                              
################################################################################
################################################################################

ORACLE_BASE=/u01/app/oracle
ORACLE_HOME=/u01/app/oracle/product/18.4.0/db_1
ORACLE_SID=orclcdb
SQLPLUS_HOME=/u01/app/oracle/product/18.4.0/db_1/bin/sqlplus

discover_1(){
val1=$(sqlplus -s / as sysdba<<EOM
set heading OFF termout ON trimout ON feedback OFF
set pagesize 0
select version from dba_registry where comp_id='XDB';
EOM
)
  echo "${val1}"
  if [ "${val1}" = "18.0.0.0.0" ]
   then
     echo "XDB is installed"
     mitigate_1
    else
      echo "XDB is not installed"
      return 0
   fi
}

mitigate_1(){
 echo "Following Users have "ALTER USER" privileges and recommended to revoke." 
 res1=$(sqlplus -s / as sysdba<<EOM
        set heading OFF termout ON trimout ON feedback OFF 
        set pagesize 0
        SELECT 'REVOKE ALTER USER FROM '|| GRANTEE ||';' FROM DBA_SYS_PRIVS WHERE PRIVILEGE = 'ALTER USER' AND GRANTEE NOT IN ('SYS','DBA'); 
EOM
        )
 echo $res1 
}

### main ###
ver=$(sqlplus -s / as sysdba <<EOM
      set heading OFF termout ON trimout ON feedback OFF
      set pagesize 0
      select version from v\$instance;
EOM
     )
#echo 'version='$ver

case $ver in
  '18.0.0.0.0')
     echo "Test for version 18c"
     discover_1
     ;;
  '19.0.0.0')
     echo "Test for version 19c"
     ;;
  *)
     echo "Incompatible Oracle Version"
     ;;
esac
### main ###
