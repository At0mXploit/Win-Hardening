Set-ADdomain -Identity wyrmwood.local -Replace @{"ms-DS-MachineAccountQuota"="0"} -Verbose
