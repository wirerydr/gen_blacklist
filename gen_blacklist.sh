#! /bin/bash
#################################################################################
#     File Name           :     gen_blacklist.sh
#     Created By          :     wirerydr
#     Creation Date       :     [2016-08-25 14:24]
#     Last Modified       :     [2016-08-26 15:23]
#     Description         :     Creates a blacklist from various sources
#################################################################################
# Originally derived from:
#   https://community.ubnt.com/t5/EdgeMAX/Emerging-Threats-Blacklist/m-p/676515#M20648
#################################################################################


#################################################################################
# Start of configuration section												#
#################################################################################

### Blacklist sources (READONLY) - comment out any that are undesired.
###
declare -a BLACKLISTSOURCES
	BLACKLISTSOURCES+=('http://pgl.yoyo.org/as/iplist.php')
	BLACKLISTSOURCES+=('http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt')
	BLACKLISTSOURCES+=('http://www.spamhaus.org/drop/drop.txt')
	BLACKLISTSOURCES+=('http://www.spamhaus.org/drop/edrop.txt')
	BLACKLISTSOURCES+=('http://www.okean.com/sinokoreacidr.txt')
	BLACKLISTSOURCES+=('http://www.myip.ms/files/blacklist/general/latest_blacklist.txt')
	BLACKLISTSOURCES+=('http://lists.blocklist.de/lists/all.txt')
declare -r BLACKLISTSOURCES

### Filename of Whitelist containing IPs and/or range(s) to be removed from the
### blacklist.  Leave empty if not needed.
readonly WHITELISTFILENAME="whitelist.lst"

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
    ERRCD+=([NOTWRITABLE]=93)   # File / directory not writable.
    ERRCD+=([CREATEFAILED]=92)  # Failure to create file / directory.
declare -r ERRCD            # Once array is constructed, lock it down readonly


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
	TMPDIRNAME=$(mktemp --directory "/tmp/$PROGNAME.tmpdir.XXXXXXXX")

	### Create a flagfile indicating this is a tmpdir and can safely
	### be cleaned up pre-exit.
	touch "${TMPDIRNAME}/.tmpdir_can_be_deleted"

	### Return the name of the new tmpdir to the caller via UpVar
	local "$1" && UpVar $1 "$TMPDIRNAME"
}


### function CleanupBeforeExit
###
### Cleans up various artifacts (e.g. temporary-directories) before this
### script exits.
###
### Args:	none
###
### Ret:	none
###
CleanupBeforeExit()
{
	### Remove tmpdir and its contents if detected
	###
	if [[ -f "${WORKINGDIR}/.tmpdir_can_be_deleted" ]]
	then
		rm -fr ${WORKINGDIR}
	fi

	### Return to original directory
	###
	cd ${ORIGDIR}
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
			>&2 echo "Getting updated list: ${BLACKLIST}"
			curl -# -O ${BLACKLIST}
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
	local STRIPPEDLIST="02_stripped.txt"
	local DEDUPEDLIST="03_deduplicated.txt"
	local WHITEADDEDLIST="04_whitelistadded.txt"

	### Count the number of stripped (but not unique or aggregated) ranges
	#
	>&2 echo "Count (non-stripped, non-unique, non-aggregated): $(sed -n '$=' ${ORIGLIST})"

	### Strip out everything except for the IPv4 addresses
	#
	sed							\
		-e '/^#/ d'				\
		-e '/[:\::]/ d'			\
		-e 's/ .*// g'			\
		-e 's/[^0-9,.,/]*// g'	\
		-e '/^$/ d'				\
		-e '/\//!s/$/\/32/ g'	\
		< ${ORIGLIST} >${STRIPPEDLIST}

	### Count the number of stripped (but not unique or aggregated) ranges
	#
	>&2 echo "Count (STRIPPED, non-unique, non-aggregated): $(sed -n '$=' ${STRIPPEDLIST})"

	### Sort, and remove any duplicates
	#
	sort -u ${STRIPPEDLIST} >${DEDUPEDLIST}

	### Count the number of stripped, deduplicated (but not aggregated) ranges
	#
	>&2 echo "Count (STRIPPED, UNIQUE, non-aggregated): $(sed -n '$=' ${DEDUPEDLIST})"

	### Remove any whitelisted ip's from LocalWhitelist.txt
	#
	if [[ -r ${WHITELIST} ]]
	then
		>&2 echo "Removing whitelisted IPs/Ranges in ${WHITELIST}"
		comm -23 ${DEDUPEDLIST} <(sort -u ${WHITELIST}) >${WHITEADDEDLIST}
	else
		>&2 echo "No whitelist specified/found - skipping"
		cp ${DEDUPEDLIST} ${WHITEADDEDLIST}
	fi

	### Count the number of stripped, deduplicated (but not aggregated) ranges including whitelists
	#
	>&2 echo "Count (STRIPPED, UNIQUE + WHITELISTED, non-aggregated): $(sed -n '$=' ${WHITEADDEDLIST})"

	### Optimize the list into as few prefixes as possible
	#
	aggregate -m 32 -o 32 -q <${WHITEADDEDLIST} >${CLEANLIST}

	### Count the number of stripped, deduplicated (but not aggregated) ranges including whitelists
	#
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


### function ErrExit
###
### Emits the specified error message and then terminates the script with the
### specified error code.
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

    printf "$ERRMSG\n" 1>&2
    exit $EXITCODE
}



main()
{
	local CONCATENATED_LIST_NAME="01_concatenated_blacklist.txt"
	local BLACKLIST_FILENAME="blacklist.txt"

	if [[ -r ${WHITELISTFILENAME} ]]
	then
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

	### Clean up the new list (e.g. strip out all non-IPv4, dupes, etc.)
	#
	CleanupBlacklist ${CONCATENATED_LIST_NAME} ${BLACKLIST_FILENAME} ${WHITELISTFILE}

	### Output the finalized blacklist to STDOUT
	#
	cat ${BLACKLIST_FILENAME}
}



trap CleanupBeforeExit EXIT
main
exit 0

