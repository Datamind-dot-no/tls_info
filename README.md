# tls_info
Script to fetch TLS/SSL information from host(s) in general, and to test for decoding of TLS traffic by certificate replacement with a custom (corporate) certificate, AKA MITM

created initially for use on macOS, relies on openssl

Compares each host certificate issuer to that of a reference host which is known to be TLS inspected and reports if there is a match.

Without verbosity switch, outputs only matching hosts, space separated.

### USAGE
tls_info.sh [OPTIONS] [URL]

### ARGUMENTS
	0. use embedded list of URLs DEFAULT_HOSTS
	1. URL (string): URL to display SSL certificate information for. Should not have a scheme components (ex., https://).

		 Ex: www.noahh.io

	 	 If a value matching the expression: /-*[Hh](?:elp)?$/ is provided this help text will be printed.

### OPTIONS
	--details      show site certificate details
	--verbose, -v  show verbose processing details
	-vv            verbose level 2
	-vvv           verbose level 3
	--trim,-t      Removes math garble (ex., 00:ae:86:12:f2:53:71:57:11)
		 from the output. Text that a human would most likely
		 not be able to make sense of
	--page,-p      Page the potentially long output. The $PAGER
		 environment variable must be configured.

### BEHAVIOUR
Prints matching hosts ssl certificate issuer CN stdout, or optionally more verbose certificate information
