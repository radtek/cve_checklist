#!/usr/bin/bash
#. ./oracle_param.ini

ORACLE_BASE=/u01/app/oracle
ORACLE_HOME=/u01/app/oracle/product/18.4.0/db_1
ORACLE_SID=orclcdb
SQLPLUS_HOME=/u01/app/oracle/product/18.4.0/db_1/bin/sqlplus

sql_1(){
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
else
 echo "XDB is not installed"
fi
}

ver=$(sqlplus -s / as sysdba <<EOM
set heading OFF termout ON trimout ON feedback OFF
set pagesize 0
select version from v\$instance;
EOM
)
#echo 'version='$ver

case $ver in
  '18.0.0.0.0')
     echo "\nTest for version 18c"
     sql_1;
     ;;
  '19.0.0.0')
     echo "\nTest for version 19c"
     ;;
  *)
     echo "\nIncompatible Oracle Version"
     ;;
esac

