SentinelOne Agent Integration for DefenseStorm

This integration is intended to be installed on the DefenseStorm DVM.  You should perform the install as the "root" user and the installation should be done in the /usr/local/ directory.

1. Pull the repository and submodules:

	git clone --recurse-submodules https://github.com/DefenseStorm/sentineloneEventLogs.git

2. If this is the first integration on this DVM, do the following:
	
	• Edit /etc/syslog-ng/syslog-ng.conf.d and add local7 to the excluded list for filter f_syslog3 and filter f_messages.
	  The lines should look like the following:

		filter f_syslog3 { not facility(auth, authpriv, mail, local7) and not filter(f_debug); };
		filter f_messages { level(info,notice,warn) and not facility(auth,authpriv,cron,daemon,mail,news,local7); };

	 • Run the following command to restart syslog-ng
	 
		service syslog-ng restart

3. Run the following command to copy the template config file and update the settings:

		cp sentineloneEventLogs.conf.template sentineloneEventLogs.conf

4. Edit the configuration in the sentineloneEventLogs.conf file:

	• Generate an API token from the Settings page of the SentinelOne Management Console.
	• Your Site Name is found in the upper-left corner of the SentinelOne Management Console.
	• Your Console Name is the host portion of the domain name in your SentinelOne Management Console
		URL.  for example "myhost" is the Console Name for "myhost.sentinelone.net".
	• Add the following to the config.d file:
		
		token = <API Token generatet in SentinelOne Management Console
		site = <Site Name>
		Console = <Console Name>

5. Add the following entry to the root crontab so the script will run every 5 minutes:

		*/5 * * * * cd /usr/local/sentineloneEventLogs; ./sentineloneEventLogs.py
