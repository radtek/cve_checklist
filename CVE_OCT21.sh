#!/usr/bin/bash
. ./oracle_param.ini
#
################################################################################
#                              CVE-Validate                                   
#                         12.1.0.2, 12.2.0.1, 19c                              
# Sample script that checks the DB version and execute a check following       
# by recommendation. 
# Create oracle_param.ini file with defined variables                                                         
# Both script and ini required to have u+x permission
# Sample exection
# $./CVE-2021-2333.sh
# 
# Change History                                                               
# 15/10/2021  Deepak Baranwal  Original code. This is a template for creating     
#                              new Bash shell scripts.                            
#                              Add new history entries as needed.                 
#                                                                              
#                                                                              
################################################################################
################################################################################
#
# Remove the local Variables or else update them in oracle_param.ini file
#ORACLE_BASE=/u01/app/oracle
#ORACLE_HOME=/u01/app/oracle/product/18.4.0/db_1
#ORACLE_SID=orclcdb
#SQLPLUS_HOME=/u01/app/oracle/product/18.4.0/db_1/bin/sqlplus
################################################################################
######################
### CVE Test Included
# CVE-2021-2333, CVE-2021-2329, CVE-2021-2337
# CVE-2019-17545
# CVE-2021-2330
#
#
#
############ End of comments section #####

discover_2330_2(){
#
# declare in main as: discover_2330_2_return=$?
#
val1=$(sqlplus -s / as sysdba<<EOM
set heading OFF termout ON trimout ON feedback OFF
set pagesize 0
SELECT GRANTEE FROM DBA_SYS_PRIVS WHERE PRIVILEGE = 'CREATE TABLE' and GRANTEE NOT IN ('DBA','SYS','SYSTEM');
EOM
)
 if [ ${#val1} > 0 ]
 then
  echo "Following users have CREATE TABLE privileges, if not necessary please revoke."
  echo "${val1}"
  discover_2330_2_return=1
 else
  discover_2330_2_return=0
 fi
  return "$discover_2330_2_return"
}


discover_2333_1(){
#
# declare in main as: discover_2333_1_return=$?
#
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
     discover_2333_1_return=1
    else
      echo "XDB is not installed"
      discover_2333_1_return=0 
   fi
   return "$discover_2333_1_return"
}

discover_17545_1(){
#
# declare in main as: discover_17545_1_return=$?
#
val1=$(sqlplus -s / as sysdba<<EOM
set heading OFF termout ON trimout ON feedback OFF
set pagesize 0
select value from v\$option where parameter='Spatial';
EOM
)
  if [ "${val1}" = "TRUE" ]
   then
     echo "Oracle Spatial is installed"
     discover_17545_1_return=1
    else
      echo "Oracle Spatial is not installed"
      discover_17545_1_return=0
   fi
   return "$discover_17545_1_return"
}

discover_17545_2(){
#
# declare in main as: discover_17545_2_return=$?
#
val1=$(sqlplus -s / as sysdba<<EOM
set heading OFF termout ON trimout ON feedback OFF
set pagesize 0
select status from dba_registry where comp_id='SDO';
EOM
)
  if [ "${val1}" = "VALID" ]
   then
     echo "Oracle Spatial SDO is configured"
     discover_17545_2_return=1
    else
      echo "Oracle Spatial SDO is not configured"
      discover_17545_2_return=0
   fi
return "$discover_17545_2_return"
}

########################################################
########## Mitigation Block Begin ######################
########################################################
mitigate_2333_1(){
 echo " "
 echo "If the Database option "Oracle XDB" is not required for this database, "
 echo "Consider Revoke the system privileges or Remove the XML DB from the database."
 echo "Commands are created in sql script drop_xdb.sql"
 cat "--- The catnoqm.sql script to drops XDB component from the Database." >  drop_xdb.sql
 cat "--- For Clustered Database Run the commands from any one of the node" >> drop_xdb.sql
 cat "spool xdb_removal.log" 												>> drop_xdb.sql
 cat "set echo on;" 														>> drop_xdb.sql
 cat "connect / as sysdba" 													>> drop_xdb.sql
 cat "shutdown immediate;" 													>> drop_xdb.sql
 cat "startup" 																>> drop_xdb.sql
 cat "@?/rdbms/admin/catnoqm.sql" 											>> drop_xdb.sql
 cat "spool off;" 															>> drop_xdb.sql
 
 echo "Following Users have "ALTER USER" privileges and recommended to revoke." 
 res1=$(sqlplus -s / as sysdba<<EOM
        set heading OFF termout ON trimout ON feedback OFF 
        set pagesize 0
        SELECT 'REVOKE ALTER USER FROM '|| GRANTEE ||';' FROM DBA_SYS_PRIVS WHERE PRIVILEGE = 'ALTER USER' AND GRANTEE NOT IN ('SYS','DBA','SYSTEM'); 
EOM
        )
 echo $res1 
}

mitigate_2330_2(){
 echo "Commands to Revoke CREATE TABLE privilege, spool file created as CVE-2021-2330.sql" 
 sqlplus -s / as sysdba<<EOM
        set heading OFF termout ON trimout ON feedback OFF 
        set pagesize 0
        spool CVE-2021-2330.sql
        SELECT 'REVOKE CREATE TABLE FROM '|| GRANTEE ||';' FROM DBA_SYS_PRIVS WHERE PRIVILEGE = 'CREATE TABLE' AND GRANTEE NOT IN ('SYS','DBA','SYSTEM'); 
        spool off; 
EOM
}

mitigate_17545_1(){
 echo "If the Database option "Oracle Spatial" is not required for this database, Consider LOCK & EXPIRE account status or rather DROP user."
 echo "ALTER USER MDSYS ACCOUNT LOCK PASSWORD EXPIRE;"
 echo "ALTER USER MDDATA ACCOUNT LOCK PASSWORD EXPIRED;"
 echo "or"
 echo "DROP USER MDSYS CASCADE;"
 echo "DROP USER MDDATA CASCADE;"
}

########################################################
########## Main Block   ################################
########################################################

ver=$(sqlplus -s / as sysdba <<EOM
      set heading OFF termout ON trimout ON feedback OFF
      set pagesize 0
      select version from v\$instance;
EOM
     )
#echo 'version='$ver

discover_2333_1_return=$?
discover_1 
if [ "$discover_2333_1_return" == 1 ] 
then
    mitigate_2333_1
fi

discover_2330_2_return=$?
discover_2330_2
if [ "$discover_2330_2_return" == 1 ]
then
    mitigate_2330_2
fi

discover_17545_2_return=$?
discover_1 
if [ "$discover_17545_2_return" == 1 ] | [ "$discover_17545_1_return" == 1 ]
then
    mitigate_17545_1
fi

### main ###
########################################################
