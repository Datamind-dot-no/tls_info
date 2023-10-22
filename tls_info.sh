#!/usr/bin/env zsh

## Script to fetch TLS/SSL information from host(s) in general, and to test for decoding of
# TLS traffic by certificate replacement with a custom (corporate) certificate, AKA MITM
#
# created initially for use on macOS, relies on openssl

# Reference host to compare issuer certificate, a host we know TLS is being inspected for
# ToDo: turn hardcoded ref_host into cli argument
ref_host="datamind.no"

# List of default hosts to test for direct access to MS services on macOS grabbed from:
# https://learn.microsoft.com/en-us/azure/active-directory/develop/apple-sso-plugin#required-network-configuration
# added explicit example hosts for wildcards in the list
# *.cdn-apple.com
# *.networking.apple
read -r -d '' DEFAULT_HOSTS << DEFAULT_HOSTS_BLOCK
$ref_host
updates.cdn-apple.com
app-site-association.networking.apple
login.microsoftonline.com
login.microsoft.com
sts.windows.net
login.partner.microsoftonline.cn
login.chinacloudapi.cn
login.microsoftonline.us
login-us.microsoftonline.com
DEFAULT_HOSTS_BLOCK
#echo "$DEFAULT_HOSTS"

# For Apple services, here is the documentation: https://support.apple.com/en-us/HT210060
# And here are some explicit hosts you could use instead of wildcards:
# cdn.apple-cloudkit.com
# cdn.apple-livephotoskit.com
# cdn.icloud-content.com
# icons.axm-usercontent-apple.com


function show_help() {
cat << HELPTEXT
TLS Info - Displays information about the provided URL's SSL certificate.

Compares each host certificate issuer to that of a reference host which is known to be
TLS inspected and reports if there is a match.

Without verbosity switch, outputs only matching hosts, space separated.

USAGE
tls_info.sh [OPTIONS] [URL]

ARGUMENTS
	0. use embedded list of URLs DEFAULT_HOSTS
	1. URL (string): URL to display SSL certificate information for. Should
		 not have a scheme components (ex., https://).

		 Ex: www.noahh.io

	 	 If a value matching the expression: /-*[Hh](?:elp)?$/
		 is provided this help text will be printed.
OPTIONS
	--details      show site certificate details
	--verbose, -v  show verbose processing details
	-vv            verbose level 2
	-vvv           verbose level 3
	--trim,-t      Removes math garble (ex., 00:ae:86:12:f2:53:71:57:11)
		 from the output. Text that a human would most likely
		 not be able to make sense of.

--page,-p        Page the potentially long output. The $PAGER
		 environment variable must be configured.

BEHAVIOUR
Prints matching hosts ssl certificate issuer CN stdout, or optionally more verbose certificate information
HELPTEXT
}


# Options
while [ ! -z "$1" ]; do
	case "$1" in
		--verbose|-v)
			verbose_level=1
			;;
		-vv)
			verbose_level=2
			;;
		-vvv)
			verbose_level=3
			;;
		--details|-d)
			cert_details=true
			;;
		--trim|-t)
			trim=true
			;;
		--page|-p)
			# Check $PAGER environment variable is configured
			if [[ -z "$PAGER" ]]; then
				echo "Error: Page option provided but \$PAGER environment variable not set" >&2
				exit 1
			fi
			page=true
			;;
		--help|-h)
			show_help "$0"
			exit 1
			;;
		*)
			host="$1"
			;;
	esac
	shift
done


# Arguments
if [ -z "$host" ]; then
	# echo "Error: host argument must be provided" >&2
	hosts="$DEFAULT_HOSTS"
elif ! [[ "$host" =~ ^([a-zA-Z0-9]+\.)+[a-zA-Z0-9]+$ ]]; then
	echo "Error: Invalid host \"$host\"" >&2
	exit 1
else
	# when a single host is specified
	hosts="$host"
fi


function get_certs() {
	local the_host=$1
	[[ $verbose_level -ge 1 ]] && echo '' && echo "testing host: [$the_host]"

	# Openssl trick for getting cert chain debug info:
	# https://serverfault.com/a/661982/276428
	local tls_info=$( echo | openssl s_client -showcerts -servername "$the_host" -connect "$the_host:443" 2> /dev/null )
	[[ $verbose_level -ge 3 ]] && echo "$tls_info"

	local cert_issuer_line=$( grep 'issuer=' <<< "$tls_info" )
	cert_issuer=$( awk -F 'issuer=' '{print $2}' <<< "$cert_issuer_line" )
	[[ $verbose_level -ge 2 ]] && echo "cert_issuer: [$cert_issuer]"
	cert_issuer_cn=$( awk -F 'CN = ' '{print $2}' <<< "$cert_issuer_line" )
	cert_issuer_cn=$( awk -F ',' '{print $1}' <<< "$cert_issuer_cn" )
	[[ $verbose_level -ge 2 ]] && echo "cert_issuer_cn: [$cert_issuer_cn]" && echo ''

	if [[ "$cert_details" ]]; then
		local cert_details=$(openssl x509 -inform pem -noout -text <<< "$tls_info")
		echo "$cert_details"
	fi
}


# main()
results=''

# get reference host certificate issuer Common Name
get_certs "$ref_host"
ref_host_cert_issuer="$cert_issuer_cn"
[[ $verbose_level -ge 1 ]] && echo "Reference host certificate issuer CN: [$ref_host_cert_issuer]"

while read -r a_host; do
	# echo "$a_host"
	get_certs "$a_host"
	if [[ "$ref_host_cert_issuer" == "$cert_issuer_cn" ]]; then
		[ -z "$results" ] && results="$a_host" || results="$results $a_host"
		[[ $verbose_level -ge 1 ]] && echo "[$a_host] is possibly TLS inspected using cert [$cert_issuer_cn]"
	fi
done <<< "$hosts"
echo "$results"
