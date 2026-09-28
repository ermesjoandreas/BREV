#!/bin/bash
# Probe: undocumented AXReplaceRangeWithText on InputLab's app, window, text field and focused element,
# with B (NSTextInputClient) focused and with A focused. Does any text reach B or A?
source "$(dirname "$0")/../lib.sh"
lab_start t12-axreplace -- --ttl 60 && sleep 0.8
for f in B A; do cmd focus$f; echo "== focus $f"; "$AX" $LPID --replace; sleep 0.3; done
lab_stop
grep -E "insertText|setMarkedText|A keyDown|B keyDown|attributedSubstring|characterIndex" $LOG || echo "(no text reached A or B)"
