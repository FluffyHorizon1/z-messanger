#!/bin/bash
# Self-contained GUI end-to-end with a real window manager (openbox) so focus
# and activation are reliable. Two isolated app instances (separate HOME +
# separate DBus session) side by side; drive each by activating its window
# then clicking/typing. Captures a real two-device encrypted conversation.
set -x
export DISPLAY=:95
export LIBGL_ALWAYS_SOFTWARE=1
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP=$ROOT/app/build/linux/x64/release/bundle/zapp
S=/tmp/gui_shots
mkdir -p $S; rm -f $S/*.png
rm -rf /tmp/zh_a /tmp/zh_b; mkdir -p /tmp/zh_a /tmp/zh_b

pkill -9 -f bundle/zapp; pkill -9 -f "server/server.js"; pkill -9 openbox; pkill -9 Xvfb; sleep 2
Xvfb :95 -screen 0 2600x900x24 >/dev/null 2>&1 &
sleep 3
openbox --config-file /tmp/ob/rc.xml >/dev/null 2>&1 &
sleep 2
(cd "$ROOT" && PORT=8080 LOG_LEVEL=info node server/server.js >/tmp/relay_gui.log 2>&1) &
sleep 1

launch() { setsid dbus-run-session -- env HOME=$1 DISPLAY=:95 LIBGL_ALWAYS_SOFTWARE=1 $APP >/tmp/zapp_$(basename $1).log 2>&1 </dev/null & }
realwin() { for w in $(xdotool search --class zapp 2>/dev/null); do xdotool getwindowgeometry $w 2>/dev/null | grep -q 1280x720 && [ "$w" != "$1" ] && echo $w; done | tail -1; }
act() { wmctrl -i -a $1 2>/dev/null; xdotool windowactivate $1 2>/dev/null; sleep 0.6; }
# click at window-relative coords: $1=win $2=rx $3=ry [settle]
clk() { act $1; eval "$(xdotool getwindowgeometry --shell $1)"; xdotool mousemove $((X+$2)) $((Y+$3)) click 1; sleep "${4:-1}"; }
typ() { act $1; xdotool type --delay 25 "$2"; sleep 0.5; }
paste() { act $1; xdotool key ctrl+v; sleep 1; }

launch /tmp/zh_a; sleep 9
A=$(realwin ""); wmctrl -i -r $A -e 0,0,0,1280,720; sleep 1
launch /tmp/zh_b; sleep 9
B=$(realwin "$A"); wmctrl -i -r $B -e 0,1300,0,1280,720; sleep 1
echo "ALICE=$A BOB=$B"
import -window root $S/00_onboarding.png

clk $A 640 315; typ $A "Alice"; clk $A 640 485 7
clk $B 640 315; typ $B "Bob"; clk $B 640 485 7
import -window root $S/01_home.png

# Alice: Add contact -> copy her code
clk $A 1187 675 3
clk $A 640 548 1
ALICE_CODE=$(act $A; xclip -selection clipboard -o -d :95); echo "ALICE_CODE_LEN=${#ALICE_CODE}"

# Bob: Add contact -> PASTE -> paste Alice code -> add
clk $B 1187 675 3
clk $B 959 78 1
clk $B 640 176 1
paste $B
clk $B 640 321 4
import -window root $S/02_bob_added.png

# Bob: copy Bob's code
clk $B 1187 675 3
clk $B 640 548 1
BOB_CODE=$(act $B; xclip -selection clipboard -o -d :95); echo "BOB_CODE_LEN=${#BOB_CODE}"

# Alice: PASTE -> paste Bob code -> add
clk $A 959 78 1
clk $A 640 176 1
paste $A
clk $A 640 321 4
import -window root $S/03_alice_added.png

# Alice: open chat, send
clk $A 200 95 3
clk $A 620 690 1
typ $A "Hey Bob - this line is end to end encrypted."
act $A; xdotool key Return; sleep 4
import -window root $S/04_alice_sent.png

# Bob: open chat, read, reply
clk $B 200 95 3
import -window root $S/05_bob_received.png
clk $B 620 690 1
typ $B "Got it - nothing ever touches a server disk."
act $B; xdotool key Return; sleep 4
import -window root $S/06_bob_replied.png

# Alice: final (reply + delivered ticks)
act $A; sleep 3
import -window root $S/07_alice_final.png

echo "=== RELAY LOG ==="; cat /tmp/relay_gui.log
echo "DONE_GUI_E2E"
