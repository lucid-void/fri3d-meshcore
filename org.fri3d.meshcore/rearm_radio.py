# One-shot: re-arm the live radio into RX and report chip mode before/after.
# Proves the "deaf = fell out of RX" diagnosis: if RX resumes after this, the fix works.
#   cd ~/repos/MicroPythonOS/internal_filesystem
#   mpremote connect /dev/ttyACM0 run apps/org.fri3d.meshcore/rearm_radio.py
import sys
import time
if "meshcore_manager" not in sys.modules:
    sys.path.append("/apps/org.fri3d.meshcore")
import meshcore_manager as MM

m = MM.MeshCoreManager.get_instance()
r = m._radio
_MODES = {0x20: "STBY_RC", 0x30: "STBY_XOSC", 0x40: "FS", 0x50: "RX", 0x60: "TX"}

m._radio_lock.acquire()
try:
    st = r.getStatus()
    print("before: status=0x%02x mode=%s" % (st, _MODES.get(st & 0x70, "?")))
    r.clearIrqStatus()
    r.startReceive()
    st = r.getStatus()
    print("after : status=0x%02x mode=%s (want RX)" % (st, _MODES.get(st & 0x70, "?")))
finally:
    m._radio_lock.release()

c0 = m._count
time.sleep(8)
print("in 8s after re-arm: count %d->%d (any increase = receiving again)" % (c0, m._count))
