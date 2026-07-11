# Radio diagnostic snapshot for the running MeshCoreManager.
# Run WITHOUT copying to the device:
#   cd ~/repos/MicroPythonOS/internal_filesystem
#   mpremote connect /dev/ttyACM0 run apps/com.micropythonos.meshcore/diag_radio.py
#
# Read-only: takes _radio_lock non-blockingly so it can't race the worker's RX poll.
import sys
import time

if "meshcore_manager" not in sys.modules:
    sys.path.append("/apps/com.micropythonos.meshcore")
import meshcore_manager as MM

m = MM.MeshCoreManager.get_instance()
r = m._radio

print("running=%s worker=%s radio_ready=%s radio=%s" %
      (m._running, m._worker_running, m._radio_ready, r is not None))
print("rx_queue=%d tx_queue=%d count=%d packets=%d nodes=%d contacts=%d" %
      (len(m._rx_queue), len(m._tx_queue), m._count, len(m._packets), len(m._nodes), len(m._contacts)))

try:
    print("rf_sw=%s (1=RX 0=TX)" % (m._rf_sw.value() if m._rf_sw else None))
except Exception as e:
    print("rf_sw err", repr(e))

try:
    print("blocking=%s (want False)" % getattr(r, "blocking", "?"))
except Exception as e:
    print("blk err", repr(e))

try:
    print("DIO1=%s (1=RX_DONE pending)" % r.irq.value())
except Exception as e:
    print("DIO1 err", repr(e))

_MODES = {0x20: "STBY_RC", 0x30: "STBY_XOSC", 0x40: "FS", 0x50: "RX", 0x60: "TX"}
got = m._radio_lock.acquire(0)
print("got_lock=%s" % got)
if got:
    try:
        st = r.getStatus()
        print("status=0x%02x mode=%s (want RX)" % (st, _MODES.get(st & 0x70, "?")))
        print("irq=0x%03x rssi=%s snr=%s" % (r.getIrqStatus(), r.getRSSI(), r.getSNR()))
    except Exception as e:
        print("spi read err", repr(e))
    finally:
        m._radio_lock.release()

c0 = m._count
try:
    d0 = r.irq.value()
except Exception:
    d0 = None
time.sleep(3)
try:
    d1 = r.irq.value()
except Exception:
    d1 = None
print("after 3s: count %d->%d  DIO1 %s->%s" % (c0, m._count, d0, d1))

print("last packets:")
for line in m.get_packets()[:5]:
    print("  " + line)
