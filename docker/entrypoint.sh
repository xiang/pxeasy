#!/bin/sh
set -e

# Run smbd in the foreground
exec smbd --foreground --no-process-group --debug-stdout --configfile=/etc/samba/smb.conf
