gen_blacklist.sh
================

`gen_blacklist.sh` is a simple bash tool that creates a (CIDR aggregated) blacklist suitable for loading into a router's prefix
filter (in the author's case, a Ubiquiti EdgeMAX ER-L).

The blacklist is derived from one or more source-lists, which are configured at the beginning of the script.  Source lists
can be either online or local.  The resulting list will be deduplicated and aggregated.

The source list(s) may contain either route prefixes, non-prefixed host IPs, or prefixed host IPs (e.g. 192.168.1.1/32).
All entries in the resulting blacklist will be prefixed.

an optional whitelist can also be configured, in which case any contained prefixes will be removed from the final blacklist.
Note that all entries in the supplied whitelist must be prefixed.

The general processing flow is contained in the main() function near the end of the script.  Most of the rest of the script is
comprised of supporting functions.

The only tool this script relies upon is [aggregate](https://www.mankier.com/1/aggregate), which performs CIDR prefix optimization.  It is available on most
\*nix-like platforms (including EdgeMAX).  For more info see: https://www.mankier.com/1/aggregate

The resulting blacklist is outputted to _stdout_. Progress is reported to _stderr_.


USAGE EXAMPLES
--------------

**gen_blacklist.sh**
( Displays progress and resulting blacklist )

**gen_blacklist.sh >blacklist.txt**
( _Displays progress and saves blacklist to 'blacklist.txt'_ )

**gen_blacklist.sh 2>/dev/null**
( _Suppresses progress and displays resulting blacklist_ )

**gen_blacklist.sh 2>/dev/null >blacklist.txt**
( _Suppresses progress and saves blacklist to 'blacklist.txt'_ )

**gen_blacklist.sh 2>/dev/null | tee blacklist.txt**
( _Suppresses progress, displays blacklist, and also saves it to 'blacklist.txt'_ )
