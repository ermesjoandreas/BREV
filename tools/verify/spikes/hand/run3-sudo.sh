#!/bin/zsh
# Run 3: a live, never-authenticated sudo process while the spike runs.
# sudo -S reads the password from a FIFO that never gets data; -k ignores any
# cached credential, so nothing is ever elevated. Closing the FIFO gives EOF and
# sudo exits with "no password". pam.d/sudo has no pam_tid, so no prompt.
S=/private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/hand-spike
APP=$S/attest/dd/Build/Products/Release/HandSpike.app
F=$S/sudo.fifo
rm -f $F; mkfifo $F
/usr/bin/sudo -S -k -p '' /usr/bin/true < $F > $S/runs/run3-sudo-exit.txt 2>&1 &
SUDO_JOB=$!
exec 3>$F
base() { echo "$1 ps_ax=$(ps -ax -o pid= | wc -l | tr -d ' ') ps_euid0=$(ps -ax -o uid= | awk '$1==0' | wc -l | tr -d ' ') ps_euid0_ruid_me=$(ps -ax -o uid=,ruid= | awk -v me=$(id -u) '$1==0 && $2==me' | wc -l | tr -d ' ') ps_sudo=$(ps -ax -o comm= | awk -F/ '$NF=="sudo"' | wc -l | tr -d ' ')"; }
base before > $S/runs/run3-terminal-baseline.txt
open -g -j -W --stdout $S/runs/run3-with-sudo.txt $APP
echo "open_exit=$?" >> $S/runs/run3-terminal-baseline.txt
base after >> $S/runs/run3-terminal-baseline.txt
exec 3>&-
wait $SUDO_JOB
echo "sudo_exit=$?" >> $S/runs/run3-terminal-baseline.txt
rm -f $F
base cleanup >> $S/runs/run3-terminal-baseline.txt
