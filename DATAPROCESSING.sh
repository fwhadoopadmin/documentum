


cat process_NewAcTiveUserReport_v2.sh

#!/bin/bash

#cat FHDOCP.LoginLST2YRSUserReport_v2.txt| awk 'NR > 13'|sed -e "s/[[:space:]]\+/ /g"|grep -Ev "affected|exit|go|Bye"|awk '{$4="\""""$4$5"\""; print ""$0"\""}'|awk '{out=$5; for(i=5;i<=NF;i++){out=out" "$i}; print $0}'|awk '{$1="\""$1"""\"" ","; $2="\""$2"""\""","; $3="\""$3"""\""","; $4=$4","; $5="\""$6""; print $0}' > NewAcTiveUserReport_v1.txt
#cp -r  NewAcTiveUserReport_v1.txt NewAcTiveUserReport_v1.csv
#sleep 1;

datadir="/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin"

mydir="/app/documentum/dba"

old_IFS=$IFS
IFS=$'\n'
DocbaseArray=($(ls -l /app/documentum/dba |grep -i dm_start |awk '{print $9}' | cut -d  "_" -f3- |grep -v ".bak"))
IFS=$old_IFS
echo "${DocbaseArray[@]}"
len=${#DocbaseArray[*]}
for (( i=0; i<${len}; i++ )); do
        data=$(echo "${DocbaseArray[$i]}"|sed 's/^[[:space:]]*\|[[:space:]]*$//g');
        cat $datadir/$data.LoginLST2YRSUserReport_v2.txt|awk 'NR > 13'|sed -e "s/[[:space:]]\+/ /g"|grep -Ev "affected|exit|go|Bye"|awk '{$4="\""""$4$5"\""; print ""$0"\""}'|awk '{out=$5; for(i=5;i<=NF;i++){out=out" "$i}; print $0}'|awk '{$1="\""$1"""\"" ","; $2="\""$2"""\""","; $3="\""$3"""\""","; $4=$4","; $5="\""$6""; print $0}' > $datadir/$data_NewAcTiveUserReport_v1.txt
        sleep 3;
        cp -r  $datadir/$data_NewAcTiveUserReport_v1.txt  $datadir/$data_NewAcTiveUserReport_v1.csv
        sleep 1;

        #idql -Udmadmin -P $data </app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin/uselogind_last2years_v2.dql>/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin/$data.LoginLST2YRSUserReport_v2.txt

Done

$ cat uselogind_last2years_v2.dql

select c.object_name as Instance,inner.user_os_name as EID,g.group_name,inner.last_login_utc_time as lastLogin,inner.user_name as UserName
from (

select distinct(u.user_name),last_login_utc_time,user_os_name from dm_group g, dm_user u
WHERE u.user_state = 0 AND u.user_source like 'L%' and datediff(year,u.last_login_utc_time,date(today)) <= 2 and substr(user_name,1,3) != 'dm_' and ANY g.users_names in
(
   select distinct(u.user_name) FROM dm_user u WHERE u.user_state = 0 AND u.user_source like 'L%' and substr(user_name,1,3) != 'dm_' and datediff(year,last_login_utc_time,date(today)) <= 2
)) inner, dm_group g,dm_server_config c where any g.users_names= inner.user_name order by inner.user_name
go
exit


$ cat uselogind_last2years_v2.dql

select c.object_name as Instance,inner.user_os_name as EID,g.group_name,inner.last_login_utc_time as lastLogin,inner.user_name as UserName
from (

select distinct(u.user_name),last_login_utc_time,user_os_name from dm_group g, dm_user u
WHERE u.user_state = 0 AND u.user_source like 'L%' and datediff(year,u.last_login_utc_time,date(today)) <= 2 and substr(user_name,1,3) != 'dm_' and ANY g.users_names in
(
   select distinct(u.user_name) FROM dm_user u WHERE u.user_state = 0 AND u.user_source like 'L%' and substr(user_name,1,3) != 'dm_' and datediff(year,last_login_utc_time,date(today)) <= 2
)) inner, dm_group g,dm_server_config c where any g.users_names= inner.user_name order by inner.user_name
go
exit

$ cat run_last2yrs_LoginReport_v2.sh

#!/bin/bash

. /app/documentum/.profile
cd /app/documentum/dmadmin/admin/rendition
>norecords.txt

mydir="/app/documentum/dba"

old_IFS=$IFS
IFS=$'\n'
DocbaseArray=($(ls -l /app/documentum/dba |grep -i dm_start |awk '{print $9}' | cut -d  "_" -f3- |grep -v ".bak"))
IFS=$old_IFS
echo "${DocbaseArray[@]}"
len=${#DocbaseArray[*]}
for (( i=0; i<${len}; i++ )); do
        data=$(echo "${DocbaseArray[$i]}"|sed 's/^[[:space:]]*\|[[:space:]]*$//g');
        idql -Udmadmin -P $data </app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin/uselogind_last2years_v2.dql>/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin/$data.LoginLST2YRSUserReport_v2.txt

done

$ cat process_NewAcTiveUserReport_v2.sh

#!/bin/bash

#cat FHDOCP.LoginLST2YRSUserReport_v2.txt| awk 'NR > 13'|sed -e "s/[[:space:]]\+/ /g"|grep -Ev "affected|exit|go|Bye"|awk '{$4="\""""$4$5"\""; print ""$0"\""}'|awk '{out=$5; for(i=5;i<=NF;i++){out=out" "$i}; print $0}'|awk '{$1="\""$1"""\"" ","; $2="\""$2"""\""","; $3="\""$3"""\""","; $4=$4","; $5="\""$6""; print $0}' > NewAcTiveUserReport_v1.txt
#cp -r  NewAcTiveUserReport_v1.txt NewAcTiveUserReport_v1.csv
#sleep 1;

datadir="/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin"

mydir="/app/documentum/dba"

old_IFS=$IFS
IFS=$'\n'
DocbaseArray=($(ls -l /app/documentum/dba |grep -i dm_start |awk '{print $9}' | cut -d  "_" -f3- |grep -v ".bak"))
IFS=$old_IFS
echo "${DocbaseArray[@]}"
len=${#DocbaseArray[*]}
for (( i=0; i<${len}; i++ )); do
        data=$(echo "${DocbaseArray[$i]}"|sed 's/^[[:space:]]*\|[[:space:]]*$//g');
        cat $datadir/$data.LoginLST2YRSUserReport_v2.txt|awk 'NR > 13'|sed -e "s/[[:space:]]\+/ /g"|grep -Ev "affected|exit|go|Bye"|awk '{$4="\""""$4$5"\""; print ""$0"\""}'|awk '{out=$5; for(i=5;i<=NF;i++){out=out" "$i}; print $0}'|awk '{$1="\""$1"""\"" ","; $2="\""$2"""\""","; $3="\""$3"""\""","; $4=$4","; $5="\""$6""; print $0}' > $datadir/$data_NewAcTiveUserReport_v1.txt
        sleep 3;
        cp -r  $datadir/$data_NewAcTiveUserReport_v1.txt  $datadir/$data_NewAcTiveUserReport_v1.csv
        sleep 1;

        #idql -Udmadmin -P $data </app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin/uselogind_last2years_v2.dql>/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin/$data.LoginLST2YRSUserReport_v2.txt

done
$ cat mailNewAcTiveUserReport.sh

#!/bin/bash

MAILTO_ME="fredrick.o.were@dominionenergy.com"

twoyrs_report() {
echo "*************************************************************************************"
echo "*************************************************************************************"
echo "Generating Active User Report Documentum Last two years"

DIR="/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin"
cd "$DIR" && \


# delete or archive old report

lastreport="NewAcTiveUserReport_v1.csv*"

if [[ -f $lastreport ]]; then
    echo "File exist "
    echo "Archiven the file"  && cp -r $lastreport $lastreport.bak_$(date +"%m-%d-%y");
    echo "Clearing content of the oldfile" && truncate -s 0 $lastreport
else
    echo "Last report missing! Proceeding **************************************"
fi

# start afresh
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#S tep 1:
# create new data:
./run_last2yrs_LoginReport_v2.sh
sleep 5 ;


#step 2:
echo " process data"
./process_NewAcTiveUserReport_v1.sh
sleep 5;

#step 3:
echo "convert and send report "
#python "2YRLoginCovert2csv.py"
#python Convert_2YRLoginCovert2csv.py
python Convert_NewAcTiveUserReport_v1.py
sleep 5;

# finally send report

Host=$(hostname)
#echo $Host

echo "Saving copy for ansible report"
#truncate -s 0  ActiveUserReport_v1_ansible.csv
sleep 1;

cp -r "ActiveUserReport_v1.csv" "ActiveUserReport_v1_ansible.csv"

pyconvrtdata="ActiveUserReport_v1.csv"


if [ -f $pyconvrtdata ]; then
    echo "Appending todays date to the generated report " && mv "$pyconvrtdata"  "ActiveUserReport_$(date +"%m-%d-%y").csv"
    sleep 1;
    echo "Validating the file"
    file4users="ActiveUserReport_$(date +"%m-%d-%y").csv"

    if [[ -f $file4users ]]; then
        echo "$file4users exist !! Sending email to designated users"
        mail -s "Active User Report Documentum on $HOSTNAME: server " -a $file4users  $MAILTO_ME < $file4users
        sleep 5;
        rm -f $file4users
        sleep 5;
    else
        echo "$file4users missing!! Unable to send the needed report"
        usersreport="Active User Report Documentum!  Script failed to generate users final report in the last stage! manually validate "
        echo "$usersreport" > failed_usersreport
        mail -s "Active User Report Documentum  $HOSTNAME: server !! Manually validate unable to generate python report for csvfile" $MAILTO_ME < failed_usersreport
        sleep 2;
        rm -f failed_usersreport
        exit 1;
    fi

else
    echo "Pyfile repot missing ! Manually validate the report"
    pyfailedreport="Active User Report Documentum Script failed to generate csvfile on python conversion of data to csvfile! manually validate "
    echo "$failedreport" > pyfailed_report
    mail -s "Active User Report Documentum on $HOSTNAME: server !! Manually validate unable to generate python report for csvfile"   $MAILTO_ME < pyfailed_report
    sleep 2;
    rm -f pyfailed_report
    exit 1;
fi

}

#main script
#########################
twoyrs_report

$ cat Convert_NewAcTiveUserReport_v1.py

#!/usr/bin/python

import csv
import itertools
from datetime import datetime
import sys
import time
import re
timestr = time.strftime("%Y%m%d-%H%M%S")

Filepath = "/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin/NewAcTiveUserReport_v1.csv"

#header = ('last_login_utc_time', 'user_name')
#fields = ['last_login_utc_time', 'user_name']

fields = ['INSTANCE', 'EID', 'GROUP_NAME','LASTLOGIN', 'USERNAME']

reader = csv.reader(open(Filepath, "rt"), skipinitialspace=True)
for row in reader:
        row = [entry.decode("utf8") for entry in row]
        for items in row:
                if(items.isdigit()):
                        row = "\"" + items
        if any(field.strip() for field in row):
                lines = list(reader)
                lines[0] = row


with open("ActiveUserReport_v1.csv", "w") as csvfile:
        #create object
        csvwriter = csv.writer(csvfile)
        #write fields
        csvwriter.writerow(fields)
        #writing data
        csvwriter.writerows(lines)

$


$ cat formatUserreport.sh

#!/bin/bash

report() {

#echo "Generating ActiveUsersReport" 2>&1 >/dev/null;

PWDIR="/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin"

old_IFS=$IFS
IFS=$'\n'
DocbaseArray=($(ls -l /app/documentum/dba |grep -i dm_start |awk '{print $9}' | cut -d  "_" -f3- |grep -v ".bak"))
IFS=$old_IFS

len=${#DocbaseArray[*]}

##################################################################
old_IFS=$IFS
IFS=$'\n'
Dataarray=($(cat $( ls "/app/documentum/dmadmin/admin/rendition/myrenditions/ActiveUserlogin"|grep -i ".UserReport.txt*") |awk 'NR>13' |grep -vE "EMC|(C)|All|Client|affected|exit|go|By|count"|sed '/^$/d'|awk '{print $1}'|grep -v "-"))

#Dataarray=($(cat $( ls $PWDIR|grep -i ".UserReport.txt*") |awk 'NR>13' |grep -vE "EMC|(C)|All|Client|affected|exit|go|By|count"|sed '/^$/d'|awk '{print $1}'|grep -v "-"))

IFS=$old_IFS

len2=${#Dataarray[*]}
echo ""

for (( i=0; i<${len}; i++ )); do
        for (( i=0; i<${len2}; i++ )); do
                counts=$(echo "${Dataarray[$i]}"|sed 's/^[[:space:]]*\|[[:space:]]*$//g');
                data=$(echo "${DocbaseArray[$i]}"|sed 's/^[[:space:]]*\|[[:space:]]*$//g');
                echo "$data $counts";
        done;
done
exit 0
}

#main report
report


@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

[root@vdcplhdps1001 - Db2wh /]# cat  /opt/ibm/diag/ras/diag-tools/apdiag/scripts/colorreport
#!/bin/bash
cat $1 | \
        sed --e 's#\[Pass\]#\x1b[6;30;42m[Pass]\x1b[0m#g' | \
        sed --e 's#\[Done\]#\x1b[6;30;42m[Done]\x1b[0m#g' | \
        sed --e 's#\[Fail\]#\x1b[6;30;41m[Fail]\x1b[0m#g' | \
        sed --e 's#\[Fail Sev:Unknown\]#\x1b[6;30;41m[Fail Sev:Unknown]\x1b[0m#g' | \
        sed --e 's#\[Fail Sev:High\]#\x1b[6;30;41m[Fail Sev:High]\x1b[0m#g' | \
        sed --e 's#\[Fail Sev:Low\]#\x1b[6;30;46m[Fail Sev:Low]\x1b[0m#g' | \
        sed --e 's#\[Warn\]#\x1b[6;30;43m[Warn]\x1b[0m#g' | \
        sed --e 's#\[Warn Sev:Unknown\]#\x1b[6;30;43m[Warn Sev:Unknown]\x1b[0m#g' | \
        sed --e 's#\[Warn Sev:Medium\]#\x1b[6;30;45m[Warn Sev:Medium]\x1b[0m#g' |
        less -RS
[root@vdcplhdps1001 - Db2wh /]#



[root@vdcplhdps1001 - Db2wh /]# cat  /opt/ibm/diag/ras/diag-tools/apdiag/health/plugins/console_status.py
from common.apdContainerOSPluginBase import apdContainerOSPluginBase

APPLICABLE_SYSTEMS = ["Local", "Appliance", "ApplianceMini", "IDAA"]
APPLICABLE_NODES = ["Head"]


class apdConsoleStatus(apdContainerOSPluginBase):

    def get_estimated_time(self):
        self.clear_err()
        return 3

    def get_test_name(self):
        name = "Web Console Status"
        self.json_status.update_name(name)
        return name

    def test(self):
        dsserver_enabled = self.config.get_config("%s.dsserver_enabled" %
                                                  self.hostname)
        if (self.config.error):
            self.logger.debug("Unable to access %s.dsserver_enabled "
                              "configuration" % self.hostname)
            if self.container_exec is not None:
                env_dict = self.container_exec.get_os_env()
                if (self.container_exec.error):
                    msg = "Unable to access DSSERVER_ENABLED env variable"
                    self.logger.debug(msg)
                    self.print_fail(msg, "ERROR")
                    self.set_err(msg)
                    status = "ERROR"
                    return status
            else:
                self.set_err("console container at host %s is not reachable. "
                             "Please make sure console container is running."
                             % self.hostname)
                self.logger.debug(self.errmsg)
                return
            if (env_dict is None or
                    "DSSERVER_ENABLED" not in env_dict or
                    env_dict["DSSERVER_ENABLED"].strip() == ""):
                # Variable doesn't exist, assume NO
                dsserver_enabled = "YES"
                self.logger.debug("DSSERVER_ENABLED is not found in "
                                  "environment, assuming YES")
            else:
                dsserver_enabled = env_dict["DSSERVER_ENABLED"]

        self.logger.debug("dsserver_enabled is set to '%s'" % dsserver_enabled)
        if (dsserver_enabled == "NO"):
            cmd01 = "/opt/ibm/apiserver/bin/status.sh"
        else:
            cmd01 = "/opt/ibm/dsserver/bin/status.sh"
        cmd_dict = self.prepare_cmd(cmd=cmd01,
                                    args="",
                                    sudo=False,
                                    repeatCount=0,
                                    repeatInterval=1,
                                    timeout=300)

        (output, errmsg, retcode) = self.run_a_cmd(cmd_dict)

        if (self.error):
            msg = "Unable to run web console status command"
            self.print_fail(msg, "ERROR")
            self.set_err(msg)
            status = "ERROR"
            self.json_status.update_issue(summary=msg,detail=self.error)
        else:
            self.write_to_file("Command: "+cmd01+":\n")
            self.write_to_file(output+"\n\n")
            if (self.error):
                self.logger.warn("Unable to write console status to file")
                # Clear the error to make sure futher code is not affected
                self.clear_err()

        status = self.analyze(output)

        return status

    def analyze(self, output):
        foundit = False

        for line in output.split("\n"):
            if (line.find("SERVER STATUS") >= 0):
                foundit = True
                console_status = line.split(":")[1]
                console_status = console_status.strip()
                if console_status == "ACTIVE":
                    msg = "Web console status is '%s'" % console_status
                    self.print_pass(msg)
                    status = "SUCCESS"
                    self.json_status.update_success()
                elif console_status == "INACTIVE":
                    msg = "Web console status is '%s'" % console_status
                    self.print_fail(msg, "INFO")
                    self.set_err(msg)
                    status = "ERROR"
                    self.json_status.update_issue(summary=msg, detail=msg)
                else:
                    msg = "Web console status is '%s'" % console_status
                    self.print_fail(msg, "ERROR")
                    self.set_err(msg)
                    status = "ERROR"
                    self.json_status.update_issue(summary=msg, detail=msg)
        if (foundit is False):
            msg = "Web console status is not available"
            self.print_fail(msg, "ERROR")
            self.set_err(msg)
            status = "ERROR"
            self.json_status.update_issue(summary=msg, detail=msg)

        return status

    def advise(self):
        # List the suggested steps to fix the problem.
        advise_data = []
        ''' OLD ADVICE, commented out 9/7/2017:
        advise_data.append("Try running commands "
                           "'/opt/ibm/dsserver/bin/restart.sh' or "
                           "'/opt/ibm/dsserver/bin/start.sh'.")
        '''
        advise_data.append("Verify that Web Console is running.")
        self.json_status.update_action("\n".join(advise_data))
        return advise_data
[root@vdcplhdps1001 - Db2wh /]#



@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

[root@vdcplhdps1001 - Db2wh /]# cat  /opt/ibm/diag/ras/diag-tools/apdiag/health/plugins/cpu_mem_status.py
from common.apdContainerOSPluginBase import apdContainerOSPluginBase

APPLICABLE_SYSTEMS = ["Local", "Appliance", "ApplianceMini", "IDAA"]
APPLICABLE_NODES = ["Head"]


class apdCPUandMemoryStatus(apdContainerOSPluginBase):
    '''
Example Output:
'''

    def get_estimated_time(self):
        self.clear_err()
        return 10

    def get_test_name(self):
        return "CPU and Memory Status"

    def test(self):
        cmd01 = "get_system_info"

        cmd_dict = self.prepare_cmd(cmd=cmd01,
                                    timeout=100,
                                    executeas="root")

        (output, errmsg, retcode) = self.run_a_cmd(cmd_dict)

        if (self.error):
            msg = "Unable to run %s command." % cmd01
            self.print_fail(msg, "ERROR")
            self.set_err(msg)
            return "FAIL"
        else:
            self.write_to_file("Command: "+cmd01+":\n")
            self.write_to_file(output+"\n\n")
            if (self.error):
                self.logger.warn("Unable to write system info to file.")
                # Clear the error to make sure futher code is not affected
                self.clear_err()
            else:
                self.print_pass("CPU and memory statuses have been collected.")
            return "SUCCESS"

    def advise(self):
        # List the suggested steps to fix the problem.
        advise_data = []
        return advise_data


@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

[root@vdcplhdps1001 - Db2wh /]# cat  /opt/ibm/diag/ras/diag-tools/apdiag/health/plugins/process_cpu_mem_usage.py
from common.apdContainerOSPluginBase import apdContainerOSPluginBase
try:
    from cStringIO import StringIO
except Exception:
    from StringIO import StringIO


APPLICABLE_SYSTEMS = ["Local", "Appliance", "ApplianceMini", "IDAA"]
APPLICABLE_NODES = ["ALL"]

CPU_MAX_PERCENT = 80.0
MEM_MAX_PERCENT = 60.0


class apdProcessesCPUandMemUsage(apdContainerOSPluginBase):
    '''
Example Output:
(First line will not be captured - for info only)
[USER  PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND]
root    1  0.0  0.0  42920  3164 ?        Ss   13:30   0:00 /usr/sbin/init
root   23  0.0  0.0  26036  1572 ?        Ss   13:30   0:00 /usr/sbin/crond -n
...
    '''

    def get_estimated_time(self):
        self.clear_err()

        # About 4 seconds per node
        nodes_count = self.get_allnodes_count()
        if (self.error):
            # Assume 7 nodes if there was an error in getting nodes count
            return 4 * 7
        else:
            return 4 * nodes_count

    def get_test_name(self):
        return "Check Process CPU and Memory Usage"

    def test(self):
        cmd01 = 'ps aux k-pcpu | head -11 | tail -10'  # Skip header row
        cmd_dict = self.prepare_cmd(cmd=cmd01,
                                    timeout=100)
        (output, errmsg, retcode) = self.run_a_cmd(cmd_dict)
        if (self.error):
            msg = "Unable to run Process Usage (ps aux) command"
            self.print_fail(msg, "ERROR")
            self.set_err(msg)
            status = "FAIL"
            return status

        self.write_to_file("Command: "+cmd01+"\n")
        self.write_to_file(output+"\n\n")
        if (self.error):
            self.logger.warn("Unable to write process output to file")

            # Clear the error to make sure futher code is not affected
            self.clear_err()

        cmd02 = 'nproc'
        cmd_dict = self.prepare_cmd(cmd=cmd02,
                                    timeout=100)
        (num_processors, errmsg, retcode) = self.run_a_cmd(cmd_dict)
        if (self.error):
            msg = "Unable to run Process Usage (ps aux) command"
            self.print_fail(msg, "ERROR")
            self.set_err(msg)
            status = "FAIL"
            return status

        self.write_to_file("Command: "+cmd02+"\n")
        self.write_to_file(num_processors+"\n\n")
        if (self.error):
            self.logger.warn("Unable to write process output to file")

            # Clear the error to make sure futher code is not affected
            self.clear_err()

        status = self.analyze(output, int(num_processors))
        return status

    def analyze(self, output, num_processors):

        if len(output) == 0:
            msg = "Error reading processes' CPU and memory statistics"
            self.print_fail(msg, "ERROR")
            self.set_err(msg)
            status = "FAIL"

        # Check CPU & Memory columns.
        # Take into account the number of processors/cores on the node,
        # and multiply CPU_MAX_PERCENT by core count to get valid limit.
        foundit = False
        data = StringIO(output)
        total_cpu_usage = 0.0
        for line in data:
            items = line.split()
            cpu_max_percent = (num_processors * CPU_MAX_PERCENT)
            total_cpu_usage += float(items[2])
            if float(items[2]) > cpu_max_percent:
                foundit = True
                msg = "PID %s(%s) is using %s%% of the CPU" % \
                      (items[1], items[10], items[2])
                self.print_fail(msg, "ERROR")
                self.set_err(msg)
                status = "ERROR"
            if float(items[3]) > MEM_MAX_PERCENT:
                foundit = True
                msg = "PID %s(%s) is using %s%% of Memory" % \
                      (items[1], items[10], items[3])
                self.print_fail(msg, "ERROR")
                self.set_err(msg)
                status = "ERROR"
        if (total_cpu_usage > cpu_max_percent):
            foundit = True
            msg = ("Total CPU usage of all top processes is over %s%% of "
                   "available system CPU" % cpu_max_percent)
            self.print_fail(msg, "ERROR")
            self.set_err(msg)
            status = "ERROR"
        if foundit is False:
            msg = ("All processes are running within specified levels. "
                   "%s CPU cores are available." % num_processors)
            self.print_pass(msg)
            status = "SUCCESS"

        return status

    def advise(self):
        # List the suggested steps to fix the problem.
        advise_data = []
        advise_data.append("Run 'top' inside container, and hit '1' to toggle "
                           "view for individual CPU core usage.")
        ''' OLD ADVICE, commented out 9/7/2017:
        advise_data.append("Restart processes that are using too much CPU.")
        '''
        advise_data.append("Investigate processes inside container that have "
                           "high memory usage.")
        return advise_data
[root@vdcplhdps1001 - Db2wh /]#





#############################


######################################################################
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
docker exec -it Db2wh bash   #log to dashdb 

# restart services 
sudo docker exec -it Db2wh stop  && sudo docker exec -it Db2wh start 


CHECK VERSION 
sudo  docker exec -it Db2wh version 

[dashdb@ricplhadoop1010 ~]$ sudo  docker exec -it Db2wh version
#######################################################################
####      --- The IBM Db2 Warehouse versioning information ---     ####
#######################################################################
image_version=ibmdashdb/local:v3.1.0-20181203-1425-local

**************** IBM Db2 Warehouse license information ****************
 * License type             : CPU Option
 * License expiry date      : Permanent
 * License status           : Active
***********************************************************************

[dashdb@ricplhadoop1010 ~]$




On each node, remove the container by issuing the following command:
docker rm Db2wh

On each node, create the daemon.json file in the /etc/docker directory, if the file doesn't exist in that location.
Add the storage-opts option to the daemon.json file, as follows:
{
"storage-opts": [ "dm.basesize=20G" ]
}

On each node, restart the Docker engine by issuing the following command:
systemctl restart docker

On each node, confirm that the base size increased by issuing the following command and checking the Base Device Size field in the output:
docker info


Db2 Warehouse is not running, or you can't connect to it.
The output of the 

sudo  docker exec -it Db2wh status  # command shows FAILURE reported against DB2connectivity or DB2running.

Resolving the problem
Explicitly stop and restart the Db2 Warehouse services by using the following commands:
sudo docker exec -it Db2wh stop  
sudo docker exec -it Db2wh start

sudo docker exec -it Db2wh start # command (which starts only services) in an SMP or MPP environment.

sudo docker start Db2wh 	# command (which starts both the container and services) in an SMP or MPP environment. 

sudo  docker run 		# command for the Db2 Warehouse container image, which automatically starts services in an SMP or MPP environment.

 docker stop container_ID 	# Stop the container for the other version by issuing the
docker stop dashDBprevious

# Redeploy the version of Db2 Warehouse whose services you were attempting to start, as follows:
	# Stop the Docker containers on all nodes by issuing the following command:
docker stop Db2whCopy code
	# Start the Docker containers on all nodes by issuing the following command:
docker start Db2wh

Resolving the problem
Before you look for a different cause of the problem, check for clock drift by issuing the following command:

sudo docker exec -it Db2wh dbhealth check --components time_sync -v

# Advice:
        1) Verify NTP configuration settings and NTPd service status on all nodes.
	[node0101-fab(Headnode)]
    	Headnode view: node0103-fab and node0104-fab clocks are
   	 more than 10 seconds out of sync                                [Fail Sev:High]
			
	Problem: Queries fail with error SQL1229N
Stop and start the services by issuing the following commands on the head node:
docker exec -it Db2wh stop
docker exec -it Db2wh start


Redeploying after troubleshooting
If the deployment fails, perform the following steps. For an MPP deployment, perform these steps on each node of the cluster.
	Remove the failed container by issuing the following command:
docker rm Db2whCopy code
	Stop the Docker engine by issuing the following command:
systemctl stop dockerCopy code
	Restart networking by issuing the following command:
systemctl restart networkCopy code
	Start the Docker engine by issuing the following command:
systemctl start dockerCopy code
	For an MPP system, save a copy of the nodes file (/mnt/clusterfs/nodes), so that you can reuse it when you redeploy. The nodes file is located on the head node. For example, on the head node, enter the following command:
cp  /mnt/clusterfs/nodes  /tmp/nodesCopy code
	Remove the contents of the cluster file-system directory by issuing the following command:
rm -rf /mnt/clusterfs/*

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

[root@vdcplhdps1001 - Db2wh /]# history
    1  ldapsearch -LLL -H ldap://mbuldap.mbu.ad.dominionnet.com:389 -b "OU=Groups,OU=Restricted,DC=mbu,DC=ad,DC=dominionnet,DC=com" -s sub -D "CN=fredr05,OU=Users,OU=Common,DC=mbu,DC=ad,DC=dominionnet,DC=com" -x -W cn=App_UxOnPremiseBigDataTools_6
    2  ldapsearch -LLL -H ldap://mbuldap.mbu.ad.dominionnet.com:389 -b "OU=Groups,OU=Restricted,DC=mbu,DC=ad,DC=dominionnet,DC=com" -s sub -D "CN=fredr05,OU=Users,OU=Common,DC=mbu,DC=ad,DC=dominionnet,DC=com" -x -W cn='admin*'
    3  ldapsearch -LLL -H ldap://mbuldap.mbu.ad.dominionnet.com:389 -b "OU=Groups,OU=Restricted,DC=mbu,DC=ad,DC=dominionnet,DC=com" -s sub -D "CN=fredr05,OU=Users,OU=Common,DC=mbu,DC=ad,DC=dominionnet,DC=com" -x -W cn='*admin*'
    4  ldapsearch -LLL -H ldap://mbuldap.mbu.ad.dominionnet.com:389 -b "OU=Groups,OU=Restricted,DC=mbu,DC=ad,DC=dominionnet,DC=com" -s sub -D "CN=fredr05,OU=Users,OU=Common,DC=mbu,DC=ad,DC=dominionnet,DC=com" -x -W cn='*bluadmin*'
    5  ldapsearch -LLL -H ldap://mbuldap.mbu.ad.dominionnet.com:389 -b "OU=Groups,OU=Restricted,DC=mbu,DC=ad,DC=dominionnet,DC=com" -s sub -D "CN=fredr05,OU=Users,OU=Common,DC=mbu,DC=ad,DC=dominionnet,DC=com" -x -W cn='*bluusers*'
    6  ldapsearch -LLL -H ldap://mbuldap.mbu.ad.dominionnet.com:389 -b "OU=Groups,OU=Restricted,DC=mbu,DC=ad,DC=dominionnet,DC=com" -s sub -D "CN=fredr05,OU=Users,OU=Common,DC=mbu,DC=ad,DC=dominionnet,DC=com" -x -W cn=App_UxOnPremiseBigDataTools_6
    7  id App_UxOnPremiseBigDataTools_6
    8  configure_user_management --local
    9  tail -f $PRODUCT_LOGFILE

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

































########################################################################################

sudo su - dashdb
Last login: Tue Aug 18 12:35:05 EDT 2020 on pts/1
[dashdb@ricplhadoop1010 ~]$ /var/lib/docker/clusterfs/SystemConfig/ricplhadoop1010/db2



Thank you Jason for the response and for taking over this case , I am very grateful

Here is the findings on my side :  
Unable to locate binary file for  db2 to run this command ( db2 get dbm cfg) 
Will need to know the exact location where its found 
Trying to get the holistic understanding of your question, maybe it will be less cumbersome if I  just tell you what I need in the process of trying to answer your question so bear with me please

Here is what I need (we need as a team) 

I need to Use Microsoft AD Authentication that is available to us on SSL port 636 as I depicted on screen shots I sent preciously
There was no any other way to integrate/communicate in DB2 GUI to Microsoft AD without SSL/TLS (Please let me know if there is any other way we can bypass SSL with connecting to AD servers – do we have any other option in the GUI?)
SO we want LDAP connectivity to dashdb (using Microsoft AD) which in order to do that, we have to have somewhere in dashdb ( DB2-Warehouse ) to store LDAP certs, so the server will not complain about missing these certs on connection

a.	Where in the DASHDB (db2-warehouse) do we need to store these LDAP certs? 
b.	What is the file name file keeping these certs? and if we have existing file name – is it called (keystore.p12 ) & can It be updated ?


We already have the certs we just need the exact location to store them so DB2-Warehouse is able to read them … 
we have tested it in  Linux side and certs are working fine and able to communicate with ldap on port 636
 finally, 
connection from Web Console   is still failing until we resolve storing the LDAP certs in the right location  for  in DB2-Warehouse

If this does not answer your questions, then 
On the choices btw (StartTLS & LDAPS) , I would like to focus on LDAPS first and make sure its working successfully, we can revisit StartTLS later after this is all completed. 
Again>> Just reminder >> I am unable to execute this command ( ( db2 get dbm cfg))  .. need to know where that binary is located 

docker exec -it Db2wh configure_user_management  --type ad --host mbuldap.mbu.ad.domi.com --port 389 
–-realm-user-password 'AdminPassword123' --searcher-base-dn CN=db2whsearcher,CN=Users,OU=Users,OU=Common,DC=mbu,DC=ad,DC=dominionnet,DC=com 
--searcher-password 'searcherPassword'


























































































