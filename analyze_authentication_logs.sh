#!/bin/bash

# current date to check the logs with date
timestamp=$(date +%Y-%m-%d_%H-%M-%S)
# auth_log.log file contains all the logs for logins. 
# auth_log_file_path variable is storing the path destination.
auth_log_file_path="/var/log/auth_log.log"

# All the potential threat terms from the log. Added it to a regex to check if any of the term is found in the line.
# in terms of performance, using this regex will efficient than using for loop over the list of threat terms.
potential_threat_terms="failed|invalid|unauthorized|error|not|failure|/etc\.ssh/ssh_host_rsa_key|detected|attempt"


# log all the suspicious log into new file
# note, if you  do not provide path.. it will run in the relative path
suspicious_log_file_path="/home/ubuntu/investigatation_script/suspicious_activity.log"

# search for potential threats/suspicios terms in logs line by line.
# create a function as this can also be leveraged to check for similar operation in different logs.
search_suspicious_logs() {

  if [[ $line =~ $potential_threat_terms ]]; then
    echo "$timestamp - Potential threat detected: $line" >> suspicious_log_file_path
  fi
}

# Read log file line by line and check for threats
while IFS='' read -r line; do
  search_suspicious_logs "$line"
done < "$auth_log_file_path"

