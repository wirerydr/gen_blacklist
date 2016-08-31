#! /bin/bash
#################################################################################
#     File Name           :     gen_blacklist.sh
#     Created By          :     wirerydr
#     Creation Date       :     [2016-08-25 14:24]
#     Last Modified       :     [2016-08-30 23:49]
#     Description         :     Creates a blacklist from various sources
#################################################################################
#
# Derived with gratitude from Vajutza's original work at:
#   https://community.ubnt.com/t5/EdgeMAX/Emerging-Threats-Blacklist/m-p/676515#M20648
#
# This script creates a (CIDR aggregated) blacklist suitable for loading into
# a router's prefix filter (in the author's case, a Ubiquiti EdgeMAX ER-L).
# The format of the resulting blacklist can either be raw, or in such a way as
# to be compatible with an 'ipset -! -R' type command.
#
# The blacklist is derived from one or more source-lists, which are configured at
# the beginning of the script.  Source lists can be online or local.  The
# resulting list will be deduplicated and aggregated.
#
# The source list(s) may contain either route prefixes, non-prefixed host IPs, or
# prefixed host IPs (e.g. 192.168.1.1/32). The resulting blacklist will contain
# routing prefixes and unprefixed host IPs.
#
# An optional whitelist can also be configured, in which case any contained
# prefixes will be removed from the final blacklist.  Note that all entries in
# the supplied whitelist should be prefixed.
#
# The general processing flow is contained in the main() function near the end
# of this script.  Most of the rest of the script is comprised of supporting
# functions.
#
# The only tool this script relies upon is 'aggregate', which performs CIDR
# prefix optimizations.  It is available on most *nix-like platforms (including
# EdgeMAX).  For more info see: https://www.mankier.com/1/aggregate
#
# The resulting blacklist is outputted to STDOUT. Progress is reported to STDERR.
#
# USAGE EXAMPLES
#
#    gen_blacklist.sh
#		( Displays progress and resulting blacklist )
#
#    gen_blacklist.sh >blacklist.txt
#		( Displays progress and saves blacklist to 'blacklist.txt' )
#
#    gen_blacklist.sh 2>/dev/null
#		( Suppresses progress and displays resulting blacklist )
#
#    gen_blacklist.sh 2>/dev/null >blacklist.txt
# 		( Suppresses progress and saves blacklist to 'blacklist.txt' )
#
#    gen_blacklist.sh 2>/dev/null | tee blacklist.txt
# 		( Suppresses progress, displays blacklist, and also saves it to 'blacklist.txt' )
#
#################################################################################


#################################################################################
# Start of configuration section												#
#################################################################################

### Blacklist sources (READONLY) - add, remove and/or comment-out as desired
###
### Forms:  BLACKLISTSOURCES+=('http://somelist.example.com/list.txt')
###				(URL - downloads from internet)
###
###		or	BLACKLISTSOURCES+=('local_filename.txt')
###				(local file - read in locally)
###
declare -a BLACKLISTSOURCES
	BLACKLISTSOURCES+=('local_blacklist.txt')
	BLACKLISTSOURCES+=('http://lists.blocklist.de/lists/all.txt')
	BLACKLISTSOURCES+=('http://pgl.yoyo.org/as/iplist.php')
	BLACKLISTSOURCES+=('http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt')
	BLACKLISTSOURCES+=('http://www.myip.ms/files/blacklist/general/latest_blacklist.txt')
	BLACKLISTSOURCES+=('http://www.okean.com/sinokoreacidr.txt')
	BLACKLISTSOURCES+=('http://www.spamhaus.org/drop/drop.txt')
	BLACKLISTSOURCES+=('http://www.spamhaus.org/drop/edrop.txt')
declare -r BLACKLISTSOURCES

### Filename of Whitelist containing IPs and/or range(s) to be removed from the
### blacklist.  Leave empty if not needed.
###
readonly WHITELISTFILENAME="local_whitelist.txt"

### Name to use as a temporary address-set with ipset.  If provided then the
### resulting list will have the appropriate header and ipset commands
### necessary to load the list with something like 'ipset -! -R'.
### If left blank, then just the raw list will be outputted.
###
#readonly IPSETTMPNAME=""
readonly IPSETTMPNAME="geotmp"

#################################################################################
# End of configuration section - DO NOT EDIT ANYTHING BELOW
#################################################################################







### Global Variables (READONLY)
###
readonly PROGNAME=$(basename $0)
readonly PROGDIR=$(readlink -m $(dirname $0))
readonly ORIGDIR=$(pwd)
readonly ARGS="$@"

### Global Variables (WRITABLE)
WORKINGDIR="WORKINGDIR"

### Result / Error Codes (READONLY)
###
declare -A ERRCD            # Declare the array and populate it
    ERRCD+=([OK]=0)             # Successful / no error.
    ERRCD+=([BADARG]=98)        # Bad argument / parameter.
	ERRCD+=([MISSING]=97)		# File / directory missing.
	ERRCD+=([NOTREADABLE]=96)	# File / directory not readable.
    ERRCD+=([NOTWRITABLE]=93)   # File / directory not writable.
    ERRCD+=([CREATEFAILED]=92)  # Failure to create file / directory.
declare -r ERRCD            # Once array is constructed, lock it down readonly


### function AddNetworkPrefixes
###
### Takes the specified file containing one-or-more CIDR IP addresses, and
### adds the /32 network prefix to all Host IP addresses.
### 	e.g. 192.168.1.123  will become 192.168.1.123
###          192.168.1.0/24 will remain 192.168.1.0/24
###
### If a destination filename is provided then the results will be written to
### it, overwriting it if already present.  If no destination is provided, then
### the original source file will be rewritten to contain the results.
###
### Args:	$1 = Existing file containing one-or-more CIDR IP addresses (will
###				 be overwritten with results if no destination file provided)
###			$2 = (Optional) destination file to write results to (will be
###				 overwritten with results if already present).  If not
###				 provided then the source file will be written-to instead.
###
### Ret:    ${ERRCD[OK]}            = Successful.
###
### Exits:  ${ERRCD[BADARG]}        = Bad argument
###         ${ERRCD[MISSING]}       = Input file not present
###         ${ERRCD[NOTREADABLE]}   = Input file not readable
###         ${ERRCD[NOTWRITABLE]}   = Output file not writable
### 			
AddNetworkPrefixes()
{
	local INPUTFILE=${1:-notspecified}
	local OUTPUTFILE=${2:-${INPUTFILE}}

	### Verify input file is specified, present and readable.
	### Verify that output file is either present-and-writable, or can be created.
	### Exit w/error on failure.
	###
	if [[ "${INPUTFILE}" == "notspecified" ]]; then
        ErrExit "Missing argument when calling AddNetworkPrefixes()" ${ERRCD[BADARG]}
	elif [[ ! -f ${INPUTFILE} ]]; then
        ErrExit "Missing input file '${INPUTFILE}' when calling AddNetworkPrefixes()" ${ERRCD[MISSING]}
	elif [[ ! -r ${INPUTFILE} ]]; then
        ErrExit "Unreadable input file '${INPUTFILE}' when calling AddNetworkPrefixes()" ${ERRCD[NOTREADABLE]}
	elif [[ ! -f ${OUTPUTFILE} ]]; then
		touch ${OUTPUTFILE}
		if [[ $? -ne 0 ]]; then
        	ErrExit "Couldn't create output file '${OUTPUTFILE}' when calling AddNetworkPrefixes()" ${ERRCD[NOTWRITABLE]}
		fi
	elif [[ ! -w ${OUTPUTFILE} ]]; then
    	ErrExit "Unwritable output file '${OUTPUTFILE}' when calling AddNetworkPrefixes()" ${ERRCD[NOTWRITABLE]}
	fi

	### Construct sed command and its arguments/parameters
	###
	local SEDCMD="sed"
	if [[ "${OUTPUTFILE}" == "${INPUTFILE}" ]]; then
		SEDCMD+=" -i''"
	fi
	SEDCMD+=" '/\/[0-9][0-9]*/!s/$/\/32/' \${INPUTFILE}" 
	if [[ "${OUTPUTFILE}" != "${INPUTFILE}" ]]; then
		SEDCMD+=" >\${OUTPUTFILE}"
	fi

	### Execute the sed command
	###
	eval ${SEDCMD}

    return ${ERRCD[OK]}
}


### function RemoveHostPrefixes
###
### Takes the specified file containing one-or-more CIDR IP addresses, and
### strips the /32 network prefix from all Host addresses. Any non /32 prefixes
### will remain unchanged.
### 	e.g. 192.168.1.123/32 will become 192.168.1.123
###          192.168.1.0/24   will remain 192.168.1.0/24
###
### If a destination filename is provided then the results will be written to
### it, overwriting it if already present.  If no destination is provided, then
### the original source file will be rewritten to contain the results.
###
### Args:	$1 = Existing file containing one-or-more CIDR IP addresses (will
###				 be overwritten with results if no destination file provided)
###			$2 = (Optional) destination file to write results to (will be
###				 overwritten with results if already present).  If not
###				 provided then the source file will be written-to instead.
###
### Ret:    ${ERRCD[OK]}            = Successful.
###
### Exits:  ${ERRCD[BADARG]}        = Bad argument
###         ${ERRCD[MISSING]}       = Input file not present
###         ${ERRCD[NOTREADABLE]}   = Input file not readable
###         ${ERRCD[NOTWRITABLE]}   = Output file not writable
### 			
RemoveHostPrefixes()
{
	local INPUTFILE=${1:-notspecified}
	local OUTPUTFILE=${2:-${INPUTFILE}}

	### Verify input file is specified, present and readable.
	### Verify that output file is either present-and-writable, or can be created.
	### Exit w/error on failure.
	###
	if [[ "${INPUTFILE}" == "notspecified" ]]; then
        ErrExit "Missing argument when calling RemoveHostPrefixes()" ${ERRCD[BADARG]}
	elif [[ ! -f ${INPUTFILE} ]]; then
        ErrExit "Missing input file '${INPUTFILE}' when calling RemoveHostPrefixes()" ${ERRCD[MISSING]}
	elif [[ ! -r ${INPUTFILE} ]]; then
        ErrExit "Unreadable input file '${INPUTFILE}' when calling RemoveHostPrefixes()" ${ERRCD[NOTREADABLE]}
	elif [[ ! -f ${OUTPUTFILE} ]]; then
		touch ${OUTPUTFILE}
		if [[ $? -ne 0 ]]; then
        	ErrExit "Couldn't create output file '${OUTPUTFILE}' when calling RemoveHostPrefixes()" ${ERRCD[NOTWRITABLE]}
		fi
	elif [[ ! -w ${OUTPUTFILE} ]]; then
    	ErrExit "Unwritable output file '${OUTPUTFILE}' when calling RemoveHostPrefixes()" ${ERRCD[NOTWRITABLE]}
	fi

	### Construct sed command and its arguments/parameters
	###
	local SEDCMD="sed"
	if [[ "${OUTPUTFILE}" == "${INPUTFILE}" ]]; then
		SEDCMD+=" -i''"
	fi
	SEDCMD+=" 's/\/32$//' \${INPUTFILE}"
	if [[ "${OUTPUTFILE}" != "${INPUTFILE}" ]]; then
		SEDCMD+=" >\${OUTPUTFILE}"
	fi

	### Execute the sed command
	###
	eval ${SEDCMD}

    return ${ERRCD[OK]}
}


### function GetTmpdir
###
### Creates a writable temporary-directory and returns the full pathname to it.
### a hidden flagfile is placed inside the new tmpdir that can be used by an
### exit-trap to detect when to safely remove the tmpdir and its entire contents.
###
### Args:	$1 = Reference to up-scope variable that will be set to contain the
###				 full pathname of the temp-dir.
###
### Ret:	 none
###
GetTmpDir()
{
	### Create a new writable temporary-directory
	TMPDIRNAME=$(mktemp -d "/tmp/$PROGNAME.tmpdir.XXXXXXXX")

	### Create a flagfile indicating this is a tmpdir and can safely
	### be cleaned up pre-exit.
	touch "${TMPDIRNAME}/.tmpdir_can_be_deleted"

	### Return the name of the new tmpdir to the caller via UpVar
	local "$1" && UpVar $1 "$TMPDIRNAME"
}


### UpdateBlacklists
###
### Pulls in current copies of Blacklists (list of which is stored in a global
### variable) and saves them into the specified directory.  The specified
### directory must already exist and be writable.
###
### Args:	$1 = Existing, writable directory to store updated blacklists into.
###
### Ret:	none
###
UpdateBlacklists()
{
	local TARGETDIR=$1

	### Pull updated blacklists from their respective sources.  Done in a
	### subshell so as to automatically 'cd' back to the original directory
	### afterward.
	#
	(
		cd ${TARGETDIR}
		for BLACKLIST in "${BLACKLISTSOURCES[@]}"
		do
			if [[ ${BLACKLIST} =~ ^http:\/\/ ]]
			then
				>&2 echo "Pulling online list: ${BLACKLIST}"
				curl -# -O ${BLACKLIST}
			else
				### If a relative filename, then prepend the original working-dir
				###
				if [[ ! ${BLACKLIST} =~ ^\/ ]]
				then
					BLACKLIST="${ORIGDIR}/${BLACKLIST}"
				fi
				if [[ -r ${BLACKLIST} ]]; then
					>&2 echo "Adding local blacklist: ${BLACKLIST}"
					cp ${BLACKLIST} ./
					>&2 echo "######################################################################## 100.0%"
				else
					>&2 echo "local blacklist '${BLACKLIST}' not found or unreadable - skipping"
				fi
			fi
		done
	)
}


### CleanupBlacklist
###
### Cleans up a supplied blacklist (e.g. removes non-IPv4 addresses, dupes,
### etc. The result is saved to the supplied filename.
###
### Args:	$1 = Name of supplied blacklist to be cleaned up.
###			$2 = File to save the cleaned-up blacklist as (will be overwritten)
###			$3 = (optional) file containing whitelist to remove from the blacklist
###
### Ret:	none
###
CleanupBlacklist()
{
	local ORIGLIST=$1
	local CLEANLIST=$2
	local WHITELIST=${3:-none}
	local PREFIXEDWHITELIST="$(basename ${WHITELIST})_prefixed.txt"
	local STRIPPEDLIST="02_stripped.txt"
	local DEDUPEDLIST="03_deduplicated.txt"
	local WHITEADDEDLIST="04_whitelistadded.txt"

	### Count the number of ranges in the input file
	#
	>&2 echo "Count (non-stripped, non-unique, non-whitelisted, non-aggregated): $(sed -n '$=' ${ORIGLIST})"

	### Strip out all unwanted lines / data from the consolidated blacklist
	### by performing the following edits (in-order) on each line:
	###
	### -e 's/^[ \t]*//'          					= Remove any leading whitespace
	### -e '/^[<#;]/ d'       						= Delete lines containing only html tags or comments
	### -e '/[:\::]/ d'           					= Delete lines containing IPv6 IP addresses
	### -e 's/[ \t<;#].*//'   						= Truncate each line at the 1st whitespace, html-tag or start-of-comment
	### -e '/^(([0-9]){1,3}\.){3}([0-9]){1,3}/! d'	= Delete lines not starting with a valid IPv4 address
	###
	sed	-r											\
		-e 's/^[ \t]*//'							\
		-e '/^[<#;]/ d'								\
		-e '/[:\::]/ d'								\
		-e 's/[ \t<;#].*//'							\
		-e '/^(([0-9]){1,3}\.){3}([0-9]){1,3}/! d'	\
		< ${ORIGLIST} >${STRIPPEDLIST}

	### Normalize every line to have a network-prefix whether it is a range or
	### a host IP. Then display a count of the stripped (but not unique,
	### whitelisted or aggregated) ranges
	#
	AddNetworkPrefixes ${STRIPPEDLIST}
	>&2 echo "Count (STRIPPED, non-unique, non-whitelisted, non-aggregated): $(sed -n '$=' ${STRIPPEDLIST})"

	### Sort, and remove any duplicates, and then display a count of the
	### stripped and deduplicated (but not whitelisted or aggregated) ranges
	#
	sort -u ${STRIPPEDLIST} >${DEDUPEDLIST}
	>&2 echo "Count (STRIPPED, UNIQUE, non-whitelisted, non-aggregated): $(sed -n '$=' ${DEDUPEDLIST})"

	### Remove whitelisted IP's (if any) listed in the supplied whitelist file.
	### If any were removed, then display a count of the stripped, deduplicated,
	### whitelisted (but non-aggregated) ranges
	### 
	#
	if [[ -r ${WHITELIST} ]]
	then
		>&2 echo "Removing whitelisted IPs/Ranges in ${WHITELIST}"
		AddNetworkPrefixes ${WHITELIST} ${PREFIXEDWHITELIST}
		comm -23 ${DEDUPEDLIST} <(sort -u ${PREFIXEDWHITELIST}) >${WHITEADDEDLIST}
		>&2 echo "Count (STRIPPED, UNIQUE, WHITELISTED, non-aggregated): $(sed -n '$=' ${WHITEADDEDLIST})"
	else
		>&2 echo "No whitelist specified/found - skipping"
		cp ${DEDUPEDLIST} ${WHITEADDEDLIST}
	fi

	### Optimize the list into as few prefixes as possible.  Remove any network
	### prefixes for host IPs (e.g. 192.168.1.123/32 becomes 192.168.1.123).
	### then display a final count of the stripped, deduplicated, whitelisted
	### aggregated ranges
	#
	aggregate -m 32 -o 32 -q <${WHITEADDEDLIST} >${CLEANLIST}
	RemoveHostPrefixes ${CLEANLIST}
	>&2 echo "Count (FINAL STRIPPED, UNIQUE + WHITELISTED, AGGREGATED): $(sed -n '$=' ${CLEANLIST})"
}


### function UpVar
###
### Assign variable one scope above the caller
###
### Usage:  local "$1" && UpVar $1 "value(s)"
###
### Args:   $1 = Variable name to assign value to
###         $* = Value(s) to assign.  If multiple values, an array is assigned,
###              otherwise a single value is assigned.
###
### NOTE:   For assigning multiple variables, use 'UpVars'.  Do NOT use multiple
###         'UpVar' calls, since one 'UpVar' call might reassign a variable to
###         be used by another 'UpVar' call.
###
### Example:    f() { local b; g b; echo $b; }
###             g() { local "$1" && UpVar $1 bar; }
###             f  # Ok: b=bar
###
### Gratefully derived from http://www.fvue.nl/wiki/Bash:_Passing_variables_by_reference
###
UpVar()
{
    local VARNAME=$1

    if unset -v "$1"; then           # Unset & validate varname
        if (( $# == 2 )); then
            eval $1=\"\$2\"          # Return single value
        else
            eval $1=\(\"\${@:2}\"\)  # Return array
        fi
    fi
}


### function PrepareDirWritable
###
### Prepares a writable directory for use by this script.  If a directory
### matching the specified name is found, then it is tested to see if it is
### writable. If no matching directory is found then an attempt is made to
### create it, which will also result in it being writable by-default.
###
### Args:   $1  = Name (relative or absolute) of data-directory to prepare.
###
### Return: ${ERRCD[OK]}            = Directory present/created and writable.
###         ${ERRCD[BADARG]}        = Bad or missing directory name.
###         ${ERRCD[NOTWRITABLE]}   = Directory present but not writable.
###         ${ERRCD[CREATEFAILED]}  = Directory not present and create failed.
###
function PrepareDirWritable()
{
    local DIRNAME="$1"
    local RETVAL=0

    # Verify a directory name was provided  Return error if not.
    if [[ "blah$DIRNAME" == "blah" ]]; then
        ErrExit "Missing argument when calling PrepareDirWritable()." ${ERRCD[BADARG]}
    fi

    # Test if directory is writable (and therefore present). Exit if
    # true.  Otherwise if directory is present then it must not be
    # writable - exit w/err.
    if [[ -w $DIRNAME ]]; then
        return ${ERRCD[OK]}
    elif [[ -d $DIRNAME ]]; then
        ErrExit "Data directory \'$DIRNAME\' not writable." ${ERRCD[NOTWRITABLE]}
    fi

    # Directory not present.  Attempt to create specified directory (absolute
    # or relative path).  Return failure if create failed.
    mkdir -p $DIRNAME 2>/dev/null
    RETVAL=$?
    if [[ $RETVAL -ne 0 ]]; then
        ErrExit "Error creating data directory \'$DIRNAME\'." ${ERRCD[CREATEFAILED]}
    fi

    # Create succeeded.
    return ${ERRCD[OK]}
}


### function CleanupBeforeExit
###
### Cleans up various artifacts (e.g. temporary-directories) before this
### script exits.
###
### Args:   none
###
### Ret:    none
###
CleanupBeforeExit()
{
	### Remove tmpdir and its contents if detected
	###
#	if [[ -f "${WORKINGDIR}/.tmpdir_can_be_deleted" ]]; then
#	  rm -fr ${WORKINGDIR}
#	fi

	### Return to original directory
	###
	cd ${ORIGDIR}
}


### function ErrExit
###
### Emits the specified error message to STDERR and then terminates the script
### with the specified error code.
###
### If no error message is supplied then a general message will be emitted.
### If no error-code is supplied than a general error-code is used.
###
### Args:   $1 = Error message to emit
###         $2 = Error code to terminate the script with
###
### Ret:    none (terminates script with error code.)
###
ErrExit()
{
    local ERRMSG=${1:-Error occurred}
    local EXITCODE=${2:-1}

    >&2 printf "$ERRMSG\n" 1>&2
    exit $EXITCODE
}



main()
{
	local CONCATENATED_LIST_NAME="01_concatenated_blacklist.txt"
	local BLACKLIST_FILENAME="blacklist.txt"

	### If a valid, readable whitelist was provided then derive the full
	### pathname to it so it can be referenced later in the script after
	### the current-working-directory has been changed.
	#
	if [[ -r ${WHITELISTFILENAME} ]]; then
		WHITELISTFILE=$(readlink -m ${WHITELISTFILENAME})
	else
		WHITELISTFILE=""
	fi

	### Create a temporary working-directory.  Change to the temporary working
	### directory.
	#
	WORKINGDIR="WORKINGDIR" # Initialize var to hold upvar'ed results
	GetTmpDir ${WORKINGDIR}
	cd ${WORKINGDIR}

	### Create a place to save updated blacklists to, and pull them from their
	### respective sources
	#
	local NEWLISTDIR="${WORKINGDIR}/new"
	PrepareDirWritable "${NEWLISTDIR}"
	UpdateBlacklists "${NEWLISTDIR}"

	### Concatenate all newly-pulled blacklists together into a single file
	#
	cat ${NEWLISTDIR}/* >${CONCATENATED_LIST_NAME}

	### Clean up the new list (e.g. strip out all non-IPv4, dupes, etc.), and
	### then output it to STDOUT.  The format of the list will be compatible
	### with 'ipset -! -R' if a temporary set-name was configured.  Otherwise
	### the raw list will be outputted.
	#
	CleanupBlacklist ${CONCATENATED_LIST_NAME} ${BLACKLIST_FILENAME} ${WHITELISTFILE}
	if [[ "blah${IPSETTMPNAME}" == "blah" ]]; then
		cat ${BLACKLIST_FILENAME}
	else
		echo "# Generated by ipset 4.5 -N ${IPSETTMPNAME} nethash --hashsize 1024 --probes 4 --resize 20"
		local SEDCMD="sed -r 's/^/-A "
		SEDCMD+="${IPSETTMPNAME} "
		SEDCMD+="/' \${BLACKLIST_FILENAME}"
		eval ${SEDCMD}
	fi
}



trap CleanupBeforeExit EXIT
main
exit 0
