# MeshCoreManager -- background MeshCore node/radio owner (singleton).
#
# Owns the shared SX1262 and runs passively in the background, independent of any UI, so
# the badge listens (and can send on public channels) even when no MeshCore screen is
# open.  Enabled by an app-local toggle (`service_enabled` pref): MeshCoreBootService starts
# it at boot when enabled, and the Me-tab switch turns it on/off live.  UI activities attach
# as a data source.
#
# Data model (all lvgl-free; UI subscribes via add_subscriber and marshals to LVGL):
#   - nodes     : neighbors/repeaters learned from ADVERT packets (UNVERIFIED -- Ed25519
#                 signatures are not checked; see meshcore_advert.py)
#   - channels  : public group channels (default "Public" + user-added), Channel objects
#   - messages  : per-channel chat history (public group text, decoded)
#   - packets   : raw parsed-packet log (debug)
#
# Radio settings verified against MeshCore source. cr=5 (4/5) matches standard MeshCore
# nodes -- required for interop (both RX decode and TX being decodable by companion/repeater).

try:
    simulation_mode = False
    from machine import Pin
except Exception as e:
    print("MeshCoreManager: simulation mode (no machine.Pin): %s" % e)
    simulation_mode = True

from meshcore_packet import (MeshCorePacket, make_header, encode_path_len,
                             ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_GRP_TXT, PAYLOAD_TYPE_ADVERT,
                             PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_ACK)
from meshcore_channel import decode_group_text, encode_group_text, PUBLIC_CHANNEL, Channel
from meshcore_advert import (parse_advert, build_advert_appdata, advert_signed_message,
                             assemble_advert_payload, ADV_TYPE_CHAT, contact_share_uri)
# Import siblings at module load (while the app dir is on sys.path) and reference them by
# attribute later. A lazy `from meshcore_crypto import ...` inside a function runs after the
# app dir has left sys.path and fails on MicroPython ("no module named ..."); an attribute
# access on the already-imported module cannot.
import meshcore_crypto  # noqa: F401
import meshcore_dm      # noqa: F401

MESHCORE_RADIO = dict(
    freq=869.618, bw=62.5, sf=8,
    cr=8,   # 4/8 -- the MeshCore config used in Belgium (must match the local network)
    syncWord=0x12,
    preambleLength=16,
    implicit=False, crcOn=True,
    tcxoVoltage=3.0,
    useRegulatorLDO=False, blocking=True,
    currentLimit=140.0, power=22,
)

class _DummyLock:
    """No-op lock for desktop simulation / ports without _thread."""
    def acquire(self, *a):
        return True

    def release(self):
        pass


MAX_PACKETS = 100       # raw log cap
MAX_MESSAGES = 200      # per-channel history cap
MESHCORE_APP = "com.micropythonos.meshcore"
NICKNAME_PREFS = MESHCORE_APP


class MeshCoreManager:

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._radio = None
        self._radio_ready = False   # True only after a full, successful bring-up
        self._running = False
        self._rf_sw = None
        # Serialises all radio SPI (RX poll + TX) across the worker and UI threads. Both
        # talk to the SX1262 over SPI bus 2 (shared with the LCD DMA); without this, a TX
        # from a UI thread could overlap the worker's RX poll and wedge the radio.
        try:
            import _thread
            self._radio_lock = _thread.allocate_lock()
        except Exception:
            self._radio_lock = _DummyLock()
        self._subscribers = []
        self._sim_started = False
        self._rx_queue = []                      # (raw, rssi, snr) awaiting processing
        self._tx_queue = []                      # raw packet bytes awaiting transmit
        self._worker_running = False
        self._last_rx_check_ms = 0               # RX watchdog: last chip-mode check
        self._last_reinit_ms = 0                 # RX watchdog: last full re-init (rate limit)
        self._rx_bad = 0                         # consecutive not-in-RX watchdog checks
        self._count = 0
        self._seq = 0
        self._packets = []                       # raw log strings, most-recent-first
        self._nodes = {}                         # pubkey_hex -> node dict
        self._seen = []                          # recent packet hashes (dedup, FIFO)
        self._seen_set = set()
        self._channels = [PUBLIC_CHANNEL]        # Channel objects
        self._messages = {PUBLIC_CHANNEL.name: []}   # channel name -> [msg dicts]
        self._dm_messages = {}                   # contact pubkey_hex -> [msg dicts] (persisted)
        self._contacts = {}                      # contact pubkey_hex -> contact dict (persisted)
        self._pending_acks = {}                  # ack_hex -> (pubkey_hex, msg) for sent DMs
        self._pending_order = []                 # ack_hex FIFO, to cap _pending_acks
        self._load_channels()
        self._load_contacts()

    def is_running(self):
        return self._running

    # --- background-service enable toggle (app-local pref, live) ------------ #
    def is_service_enabled(self):
        """Whether the MeshCore radio service should run (persisted, default off)."""
        try:
            from mpos import SharedPreferences
            return SharedPreferences(NICKNAME_PREFS).get_bool("service_enabled", False)
        except Exception:
            return False

    def set_service_enabled(self, on):
        """Persist the toggle and start/stop the radio live (no reboot needed)."""
        on = bool(on)
        try:
            from mpos import SharedPreferences
            ed = SharedPreferences(NICKNAME_PREFS).edit()
            ed.put_bool("service_enabled", on)
            ed.commit()
        except Exception as e:
            print("MeshCore: set_service_enabled error:", repr(e))
        if on:
            self.start()
        else:
            self.stop()
        self._notify("service", on)

    def nickname(self):
        try:
            from mpos import SharedPreferences
            n = SharedPreferences(NICKNAME_PREFS).get_string("nickname", "badge")
            return n or "badge"
        except Exception:
            return "badge"

    def set_nickname(self, name):
        name = (name or "").strip()
        if not name:
            return False
        try:
            from mpos import SharedPreferences
            ed = SharedPreferences(NICKNAME_PREFS).edit()
            ed.put_string("nickname", name)
            ed.commit()
            return True
        except Exception as e:
            print("MeshCore: set_nickname error:", repr(e))
            return False

    # --- identity (Ed25519 keypair) ---------------------------------------- #
    def get_identity(self):
        """Return (pubkey32, prv64) for this node, or (None, None) if not generated."""
        try:
            import binascii
            from mpos import SharedPreferences
            p = SharedPreferences(NICKNAME_PREFS)
            pub = p.get_string("identity_pub", "")
            prv = p.get_string("identity_prv", "")
            if pub and prv:
                # MicroPython's unhexlify needs bytes (CPython also accepts str)
                return binascii.unhexlify(pub.encode()), binascii.unhexlify(prv.encode())
        except Exception as e:
            print("MeshCore: get_identity error:", repr(e))
        return None, None

    def has_identity(self):
        return self.get_identity()[0] is not None

    def node_id(self):
        """The node's 1-byte routing id = first byte of the public key, or None."""
        pub, _ = self.get_identity()
        return pub[0] if pub else None

    def generate_identity(self):
        """Generate + persist a new MeshCore Ed25519 keypair.

        SLOW (pure-Python scalar mult -- seconds on the badge); call off the UI thread.
        Returns the 32-byte public key, or None on failure.
        """
        try:
            pub, prv = meshcore_crypto.generate_keypair()
        except Exception as e:
            print("MeshCore: keygen failed:", repr(e))
            return None
        try:
            import binascii
            from mpos import SharedPreferences
            ed = SharedPreferences(NICKNAME_PREFS).edit()
            ed.put_string("identity_pub", binascii.hexlify(pub).decode())
            ed.put_string("identity_prv", binascii.hexlify(prv).decode())
            ed.commit()
            print("MeshCore: identity generated, node id 0x%02x" % pub[0])
        except Exception as e:
            print("MeshCore: save identity error:", repr(e))
        self._notify("identity", pub)
        return pub

    def contact_uri(self):
        """meshcore:// contact card for this node, to render as a QR. None if no identity."""
        pub, _ = self.get_identity()
        if pub is None:
            return None
        try:
            import binascii
            return contact_share_uri(self.nickname(), binascii.hexlify(pub).decode(),
                                     ADV_TYPE_CHAT)
        except Exception as e:
            print("MeshCore: contact_uri error:", repr(e))
            return None

    def backup_identity_to_sd(self, path="/sdcard/meshcore_identity.json"):
        """Write the identity (name + keys, hex) to the SD card. Returns (ok, info)."""
        pub, prv = self.get_identity()
        if pub is None:
            return (False, "no identity to back up")
        try:
            import binascii
            import ujson
            from mpos import sdcard
            sdcard.mount_with_optional_format("/sdcard")
            data = {
                "name": self.nickname(),
                "node_id": "%02x" % pub[0],
                "public_key": binascii.hexlify(pub).decode(),
                "private_key": binascii.hexlify(prv).decode(),
            }
            with open(path, "w") as f:
                ujson.dump(data, f)
            print("MeshCore: identity backed up to", path)
            return (True, path)
        except Exception as e:
            print("MeshCore: SD backup error:", repr(e))
            return (False, str(e))

    # --- advertising -------------------------------------------------------- #
    def advertise(self):
        """Build, Ed25519-sign, and flood a self-advert so peers learn our identity/name.

        Requires an identity.  Signing is slow (~2s) but done before touching the radio,
        so RX stays up during it.  Returns (ok, err).
        """
        import time
        pub, prv = self.get_identity()
        if pub is None:
            return (False, "no identity -- generate one first")
        try:
            ts = int(time.time())
            app_data = build_advert_appdata(ADV_TYPE_CHAT, self.nickname())
            message = advert_signed_message(pub, ts, app_data)
            signature = meshcore_crypto.sign(prv, message)     # ~2s, radio still receiving
            payload = assemble_advert_payload(pub, ts, signature, app_data)
        except Exception as e:
            print("MeshCore: advert build failed:", repr(e))
            return (False, str(e))
        if simulation_mode:
            print("MeshCore: SIM advertise (id 0x%02x, %s)" % (pub[0], self.nickname()))
            return (True, None)
        if self._radio is None:
            return (False, "radio not ready")
        pkt = MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT),
                             encode_path_len(0), b"", payload)
        try:
            self._remember(pkt.packet_hash())  # ignore the repeater's echo of our advert
        except Exception:
            pass
        self._enqueue_tx(pkt.to_bytes())   # the worker flushes it in the next RX gap
        print("MeshCore: advert queued (id 0x%02x, name '%s')" % (pub[0], self.nickname()))
        return (True, None)

    # NOTE: advertising is manual only (the "Advertise now" button). There is no periodic
    # auto-advert -- the background worker stays focused on receiving. Sending an advert
    # briefly takes the radio off RX (sign + TX), so we only do it on explicit request.

    # --- channel management ------------------------------------------------- #
    def _load_channels(self):
        try:
            from mpos import SharedPreferences
            saved = SharedPreferences(NICKNAME_PREFS).get_list("channels", []) or []
        except Exception as e:
            print("MeshCore: load channels error:", repr(e))
            saved = []
        for entry in saved:
            try:
                name = entry.get("name")
                psk = entry.get("psk")
                if name and psk and self.get_channel(name) is None:
                    self._channels.append(Channel.from_psk_base64(name, psk))
                    self._messages.setdefault(name, [])
            except Exception as e:
                print("MeshCore: skipping bad saved channel %r: %s" % (entry, e))

    def _save_channels(self):
        try:
            from mpos import SharedPreferences
            custom = [{"name": c.name, "psk": c.psk_b64}
                      for c in self._channels
                      if c.name != PUBLIC_CHANNEL.name and c.psk_b64]
            ed = SharedPreferences(NICKNAME_PREFS).edit()
            ed.put_list("channels", custom)
            ed.commit()
        except Exception as e:
            print("MeshCore: save channels error:", repr(e))

    def add_channel(self, name, psk_b64=""):
        name = (name or "").strip()
        psk_b64 = (psk_b64 or "").strip()
        if not name:
            return (False, "empty name")
        try:
            if psk_b64:
                # explicit shared key -> private channel
                ch = Channel.from_psk_base64(name, psk_b64)
            else:
                # bare name -> public hashtag channel with a name-derived key, so it
                # interoperates with other nodes' "#<name>" channel (MeshCore convention)
                ch = Channel.from_hashtag_name(name)
        except Exception as e:
            return (False, "invalid channel (%s)" % e)
        if self.get_channel(ch.name) is not None:
            return (False, "channel '%s' already exists" % ch.name)
        self._channels.append(ch)
        self._messages.setdefault(ch.name, [])
        self._save_channels()
        self._notify("channels", None)
        return (True, None)

    def remove_channel(self, name):
        if name == PUBLIC_CHANNEL.name:
            return False  # the default public channel is not removable
        if self.get_channel(name) is None:
            return False
        self._channels = [c for c in self._channels if c.name != name]
        self._messages.pop(name, None)
        self._save_channels()
        self._notify("channels", None)
        return True

    # --- lifecycle ---------------------------------------------------------- #
    def start(self):
        if self._running:
            print("MeshCoreManager: already running")
            return
        self._running = True
        if simulation_mode:
            self._ensure_worker()
            self._start_simulation()
            return
        self._ensure_worker()
        import _thread
        from mpos import TaskManager
        _thread.stack_size(TaskManager.good_stack_size())
        _thread.start_new_thread(self._radio_init_thread, ())

    @staticmethod
    def _reset_lora_via_ch32():
        """Hardware-reset the SX1262 via the CH32 expander (config reg 0x16): hold LoRa in
        reset then release, keeping LCD/aux powered.  The driver's own reset() toggles a
        dummy GPIO, so this is the only way to get a guaranteed-clean radio."""
        try:
            import time
            import mpos
            exp = getattr(mpos, "io_expander", None)
            if exp is None:
                return
            exp.config = 0x03   # LoRa held in reset, LCD on, aux on
            time.sleep_ms(100)
            exp.config = 0x13   # LoRa released, LCD on, aux on
            time.sleep_ms(100)
            print("MeshCoreManager: CH32 LoRa reset done")
        except Exception as e:
            print("MeshCoreManager: CH32 LoRa reset error:", repr(e))

    def _bring_up_radio(self):
        """Reset + configure the radio for continuous RX. Returns True on success."""
        import time
        from mpos import LoRaManager, DeviceInfo
        fri3d = DeviceInfo.hardware_id == "fri3d_2026"
        # Not ready until setBlockingCallback below succeeds. Assigning self._radio during
        # begin() is not enough: if begin() throws on a wedged radio, the chip never gets
        # setBlockingCallback and send() then fails with "'SX1262' has no attribute
        # 'blocking'". TX/RX guard on this flag so they never touch a half-configured radio.
        self._radio_ready = False
        state = None
        for attempt in (1, 2):
            self._reset_lora_via_ch32()
            if fri3d:
                self._rf_sw = Pin(46, Pin.OUT)
                self._rf_sw.value(1); print("RF_SW set to HIGH")
            self._radio = LoRaManager.radioChip
            state = self._radio.begin(**MESHCORE_RADIO)
            print("MeshCoreManager: begin state=%s (attempt %d)" % (state, attempt))
            if state == 0:
                break
            time.sleep_ms(200)  # bad begin -> reset and retry once
        # Configure RX regardless of the reported begin state (best effort).
        try:
            # Non-blocking RX, but NO DIO1 interrupt handler (callback=None -> the driver
            # arms continuous receive and calls clearDio1Action). We poll DIO1/IRQ from the
            # worker thread instead (_poll_radio_rx): the soft pin IRQ ran in the main VM
            # thread and got starved by another app's LVGL/LCD-DMA when backgrounded, which
            # dropped packets. The worker thread runs regardless of the foreground app.
            self._radio.setBlockingCallback(False, None)
            if fri3d:
                self._radio.setDio2AsRfSwitch(False)
                self._rf_sw.value(1); print("RF_SW set to HIGH")
            self._radio_ready = True
            print("MeshCoreManager: passive receive started, worker-polled (begin state=%s)" % state)
            return True
        except Exception as e:
            print("MeshCoreManager: RX setup failed:", repr(e))
            return False

    def _radio_init_thread(self):
        import time
        time.sleep(1)
        try:
            if not self._bring_up_radio():
                self._running = False
        except Exception as e:
            print("MeshCoreManager: radio init failed:", repr(e))
            self._running = False

    def restart(self):
        """Recover a wedged radio: stop, reset via CH32, and re-init (from the UI)."""
        print("MeshCoreManager: restart requested")
        self._running = False
        self._radio_ready = False    # block TX/RX until bring-up re-completes
        if simulation_mode:
            self._running = True
            return
        self._running = True
        self._ensure_worker()
        import _thread
        from mpos import TaskManager
        _thread.stack_size(TaskManager.good_stack_size())
        _thread.start_new_thread(self._radio_init_thread, ())

    def stop(self):
        if not self._running:
            return
        self._running = False
        self._radio_ready = False
        if not simulation_mode and self._radio is not None:
            try:
                self._radio.sleep(retainConfig=False)
            except Exception as e:
                print("MeshCoreManager: stop/sleep error:", repr(e))
        print("MeshCoreManager: stopped")

    # --- receive path ------------------------------------------------------- #
    def _poll_radio_rx(self):
        """Poll for a received packet from the WORKER thread and enqueue it.

        RX is serviced here rather than from a DIO1 pin interrupt: the soft IRQ ran via
        micropython.schedule in the main VM thread and was starved whenever another app
        held the CPU (its LVGL loop / LCD DMA on the shared SPI bus 2), so backgrounded RX
        dropped most packets. The dedicated worker thread runs regardless of which app is
        foreground. DIO1 is mapped to RX_DONE only, so a cheap GPIO read gates the (SPI)
        status read. The lock serialises this against TX (both do SPI on bus 2).

        Returns True if a packet was received and queued.
        """
        if not self._radio_ready or self._radio is None:
            return False
        try:
            if not self._radio.irq.value():   # DIO1 low -> nothing pending (no SPI needed)
                return False
        except Exception:
            pass  # pin read unavailable -> fall through to the SPI status check
        from drivers.lora.sx1262 import SX1262
        got = False
        self._radio_lock.acquire()
        try:
            events = self._radio.getIrqStatus()
            if events & SX1262.RX_DONE:
                rssi = self._radio.getRSSI()
                snr = self._radio.getSNR()
                msg, err = self._radio.recv()   # re-arms RX + clears IRQ (via _readData)
                if err == 0 and msg and len(msg) > 0:
                    self._rx_queue.append((bytes(msg), rssi, snr))
                    got = True
                else:
                    print("MeshCoreManager: recv err=%s" % SX1262.STATUS[err])
            else:
                # DIO1 high but no RX_DONE (unexpected): clear and re-arm so we don't spin.
                self._radio.clearIrqStatus()
                self._radio.startReceive()
        except Exception as e:
            # recv may have thrown before re-arming -> force RX back on so we don't stall.
            print("MeshCoreManager: rx poll exception:", repr(e))
            try:
                self._radio.startReceive()
            except Exception as e2:
                print("MeshCoreManager: re-arm failed:", repr(e2))
        finally:
            self._radio_lock.release()
        return got

    def _rx_pending(self):
        """True if a packet is waiting in the radio (DIO1 high) -- don't TX over it."""
        if simulation_mode or self._radio is None:
            return False
        try:
            return bool(self._radio.irq.value())
        except Exception:
            return False

    def _enqueue_tx(self, raw):
        """Queue an outgoing packet; the worker transmits it in the next RX gap. All TX flows
        through here so the worker thread is the SOLE owner of the radio (no cross-thread SPI)."""
        self._tx_queue.append(bytes(raw))

    def _rx_watchdog(self):
        """Periodically (~2s) make sure the radio is still in continuous RX, and recover it
        if not.

        In continuous mode the SX1262 shouldn't leave RX on its own, but a TX that overran or
        an SPI glitch on the LCD-shared bus can drop it to STANDBY (DIO1 never rises -> silently
        deaf) or wedge it entirely (GetStatus returns 0x00 = unresponsive on SPI). A standby
        gets a light re-arm; a hard wedge (0x00) or a persistent problem gets a full re-init."""
        if simulation_mode or self._radio is None:
            return
        import time
        now = time.ticks_ms()
        if time.ticks_diff(now, self._last_rx_check_ms) < 2000:
            return
        self._last_rx_check_ms = now
        # Bring-up never completed / a previous re-init failed -> recovery is the only option.
        if not self._radio_ready:
            self._attempt_reinit(now)
            return
        reinit = False
        if not self._radio_lock.acquire(0):
            return  # bus busy (mid RX/TX) -> check again next tick
        try:
            st = self._radio.getStatus()
            # chip mode = status bits [6:4]; 0x50 = RX (healthy).
            if (st & 0x70) == 0x50:
                if self._rx_bad:
                    print("MeshCoreManager: RX recovered")
                self._rx_bad = 0
            else:
                self._rx_bad += 1
                if self._rx_bad == 1:   # log the transition once, not every 2s
                    print("MeshCoreManager: RX watchdog -- not in RX (status 0x%02x)" % st)
                # 0x00 = chip not answering SPI (hard wedge): a startReceive can't fix it.
                if st == 0x00 or self._rx_bad >= 3:
                    reinit = True
                else:
                    self._radio.clearIrqStatus()
                    self._radio.startReceive()
        except Exception as e:
            print("MeshCoreManager: RX watchdog error:", repr(e))
            reinit = True
        finally:
            self._radio_lock.release()
        if reinit:
            self._attempt_reinit(now)

    def _attempt_reinit(self, now):
        """Recover a wedged radio via a full re-init (CH32 reset + begin + setBlockingCallback).

        Rate-limited to ~5s so a radio that's momentarily un-recoverable (e.g. the LCD is mid
        app-switch and hammering the shared SPI bus) doesn't thrash the CH32/SPI or flood the
        serial -- but it keeps retrying, so it self-heals as soon as the bus goes quiet."""
        import time
        if time.ticks_diff(now, self._last_reinit_ms) < 5000:
            return
        self._last_reinit_ms = now
        self._rx_bad = 0
        print("MeshCoreManager: radio re-init (recovering wedged radio)")
        try:
            self._bring_up_radio()   # sets _radio_ready True on success
        except Exception as e:
            print("MeshCoreManager: re-init failed:", repr(e))

    def _ensure_worker(self):
        if self._worker_running:
            return
        self._worker_running = True
        try:
            import _thread
            try:
                from mpos import TaskManager
                _thread.stack_size(TaskManager.good_stack_size())
            except Exception:
                pass  # stack sizing is device-only; fine to skip off-badge
            _thread.start_new_thread(self._process_loop, ())
        except Exception as e:
            self._worker_running = False
            print("MeshCoreManager: could not start worker:", repr(e))

    def _process_loop(self):
        import time
        while self._running:
            # 1) Service the radio first (fast: DIO1 gate + recv into the queue).
            did_rx = False
            if not simulation_mode:
                try:
                    did_rx = self._poll_radio_rx()
                except Exception as e:
                    print("MeshCoreManager: rx poll error:", repr(e))
            # 2) Process at most one queued packet (AES decode / UI notify -- CPU work that
            #    must NOT sit between recv and the next poll for long).
            did_proc = False
            if self._rx_queue:
                try:
                    raw, rssi, snr = self._rx_queue.pop(0)
                    self._ingest(raw, rssi=rssi, snr=snr)
                    did_proc = True
                except Exception as e:
                    print("MeshCoreManager: process exception:", repr(e))
            # 3) Transmit one queued outgoing packet -- but only in a gap: not right after an
            #    RX and only when no packet is mid-reception (DIO1 low). The worker is the SOLE
            #    owner of the radio, so all TX happens here (never from a UI thread).
            did_tx = False
            if (self._tx_queue and (simulation_mode or self._radio_ready)
                    and not did_rx and not self._rx_pending()):
                raw = self._tx_queue.pop(0)
                try:
                    self._transmit(raw)
                except Exception as e:
                    print("MeshCoreManager: tx drain error:", repr(e))
                did_tx = True
            # 4) Idle: run the RX watchdog (re-arm/re-init if the chip fell out of RX),
            #    then sleep briefly so we keep polling quickly. No auto-advert.
            if not did_rx and not did_proc and not did_tx:
                self._rx_watchdog()
                time.sleep(0.02)   # portable (MicroPython + CPython)
        self._worker_running = False

    @staticmethod
    def _meta(rssi, snr):
        parts = []
        if rssi is not None:
            parts.append("RSSI=%s" % rssi)
        if snr is not None:
            parts.append("SNR=%s" % snr)
        return " ".join(parts)

    def _ingest(self, msg, rssi=None, snr=None):
        self._count += 1
        try:
            pkt = MeshCorePacket.parse(msg)
        except ValueError as e:
            print("MeshCore unparseable #%d: %s  hex=%s" % (self._count, e, msg.hex()))
            self._log("#%d UNPARSEABLE (%s) %dB %s" % (self._count, e, len(msg), msg.hex()))
            return

        pkt.rssi = rssi
        pkt.snr = snr
        meta = self._meta(rssi, snr)

        # De-duplicate flooded copies (direct + via repeater carry the same payload).
        if self._is_duplicate(pkt):
            return

        if pkt.payload_type == PAYLOAD_TYPE_ADVERT:
            self._handle_advert(pkt, rssi, snr, meta)
        elif pkt.payload_type == PAYLOAD_TYPE_GRP_TXT and self._handle_group_text(pkt, rssi, meta):
            pass
        elif pkt.payload_type == PAYLOAD_TYPE_TXT_MSG and self._handle_dm(pkt, rssi, meta):
            pass
        elif pkt.payload_type == PAYLOAD_TYPE_PATH and self._handle_path(pkt):
            pass
        elif pkt.payload_type == PAYLOAD_TYPE_ACK and self._handle_ack(pkt):
            pass
        else:
            summary = pkt.summary()
            print("MeshCore packet #%d: %s  hex=%s" % (self._count, summary, msg.hex()))
        # always keep a raw log line
        self._log("#%d %s" % (self._count, pkt.summary()))

    def _remember(self, h):
        """Record a packet hash; returns False if it was already seen."""
        if h in self._seen_set:
            return False
        self._seen.append(h)
        self._seen_set.add(h)
        if len(self._seen) > 64:
            self._seen_set.discard(self._seen.pop(0))
        return True

    def _is_duplicate(self, pkt):
        try:
            return not self._remember(pkt.packet_hash())
        except Exception:
            return False

    def _handle_advert(self, pkt, rssi, snr, meta):
        try:
            adv = parse_advert(pkt.payload)
        except ValueError as e:
            print("MeshCore: advert parse error:", e)
            return
        # ignore our own advert (echoed back by a repeater)
        pub, _ = self.get_identity()
        if pub is not None and adv["pubkey"] == pub.hex():
            return
        # The badge only chats with companions -- ignore repeaters/rooms/sensors entirely.
        if adv.get("type") != ADV_TYPE_CHAT:
            return
        self._seq += 1
        node = self._nodes.get(adv["pubkey"], {})
        node.update(adv)
        node["rssi"] = rssi
        node["snr"] = snr
        node["seq"] = self._seq
        self._nodes[adv["pubkey"]] = node
        # if this companion is already a contact, refresh its live signal / last-heard
        # (contact *details* are persisted separately; live radio info stays in RAM).
        c = self._contacts.get(adv["pubkey"])
        if c is not None:
            c["rssi"] = rssi
            c["seq"] = self._seq
            # a contact's name tracks its advertised name (same pubkey) -> auto-rename on change
            new_name = adv.get("name")
            if new_name and new_name != c.get("name"):
                print("MeshCore: contact %s renamed '%s' -> '%s'" % (
                    adv["pubkey"][:8], c.get("name"), new_name))
                c["name"] = new_name
                self._save_contacts()   # persist the new name
        print("MeshCore companion: %s id=%s %s [UNVERIFIED]" % (
            node.get("name") or "?", node.get("id"), meta))
        self._notify("node", node)

    def _handle_group_text(self, pkt, rssi, meta):
        try:
            decoded = decode_group_text(pkt.payload, tuple(self._channels))
        except Exception as e:
            print("MeshCore: group decode error:", repr(e))
            decoded = None
        if not decoded:
            return False
        msg = {
            "ts": decoded["timestamp"],
            "sender": decoded["sender"] or "?",
            "text": decoded["text"],
            "rssi": rssi,
            "incoming": True,
        }
        print("MeshCore [%s] %s: %s  (%s)" % (decoded["channel"], msg["sender"], msg["text"], meta))
        self._add_message(decoded["channel"], msg)
        self._notify("message", (decoded["channel"], msg))
        self._post_notification(decoded["channel"], msg)
        return True

    # --- direct messages (1:1, X25519) ------------------------------------- #
    def _node_secret(self, node):
        """Return (and cache on the node) the 32-byte X25519 shared secret with a node.

        Needs our identity's private key and the node's public key (learned from its
        advert).  ECDH is ~0.6s on the badge, so the result is cached per node."""
        sec = node.get("secret")
        if sec is not None:
            return sec
        pub_hex = node.get("pubkey")
        _, prv = self.get_identity()
        if not prv or not pub_hex:
            return None
        try:
            import binascii
            pub = binascii.unhexlify(pub_hex.encode())
            sec = meshcore_crypto.shared_secret(prv, pub)
            node["secret"] = sec
            return sec
        except Exception as e:
            print("MeshCore: shared_secret error:", repr(e))
            return None

    def _handle_dm(self, pkt, rssi, meta):
        """Decode an incoming TXT_MSG addressed to us -- only from an added contact.

        You must add a companion to your contact list before you can exchange DMs with
        them, so we only try to decrypt against saved contacts (never random nodes)."""
        self_hash = self.node_id()
        if self_hash is None or len(pkt.payload) < 2:
            return False
        if pkt.payload[0] != (self_hash & 0xFF):
            return False  # not addressed to us -- cheap reject before any ECDH
        src_hash = pkt.payload[1]
        candidates = self._contact_candidates(src_hash)
        if not candidates:
            return False  # sender isn't a contact -> ignore (add them first to chat)
        try:
            got = meshcore_dm.decode_dm(pkt.payload, self_hash, candidates)
        except Exception as e:
            print("MeshCore: dm decode error:", repr(e))
            return False
        if not got:
            return False
        pub_hex = got["pubkey"].hex()
        contact = self._contacts.get(pub_hex, {})
        name = contact.get("name") or ("%02x" % got["src_hash"])
        msg = {"ts": got["timestamp"], "sender": name, "text": got["text"],
               "rssi": rssi, "incoming": True}
        print("MeshCore DM <%s>: %s  (%s)" % (name, msg["text"], meta))
        self._add_dm(pub_hex, msg)
        self._notify("dm", (pub_hex, msg))
        self._post_dm_notification(pub_hex, name, msg)
        # Acknowledge it (flood PATH-return with the embedded ack hash) so the sender's client
        # marks the message delivered.
        try:
            self._send_path_ack(got, pkt)
        except Exception as e:
            print("MeshCore: send ack error:", repr(e))
        return True

    def _contact_candidates(self, src_hash):
        """(pubkey_bytes, shared_secret) for each contact whose hash matches src_hash."""
        out = []
        try:
            import binascii
            for pub_hex, contact in self._contacts.items():
                if int(pub_hex[0:2], 16) != src_hash:
                    continue
                sec = self._node_secret(contact)
                if sec is not None:
                    out.append((binascii.unhexlify(pub_hex.encode()), sec))
        except Exception as e:
            print("MeshCore: candidate error:", repr(e))
        return out

    @staticmethod
    def _rand_byte():
        try:
            import os
            return os.urandom(1)[0]
        except Exception:
            import time
            return int(time.time()) & 0xFF

    def _send_path_ack(self, got, pkt):
        """Reply to a received DM with a flood PATH-return embedding its ack hash."""
        pub, _ = self.get_identity()
        if pub is None:
            return
        contact = self._contacts.get(got["pubkey"].hex())
        if contact is None:
            return
        secret = self._node_secret(contact)
        if secret is None:
            return
        ack6 = bytes(got["ack_hash"]) + bytes([0, self._rand_byte()])
        payload = meshcore_dm.build_path_ack(secret, got["src_hash"], pub[0],
                                             pkt.path, pkt.path_len_raw, ack6)
        out = MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_PATH),
                             encode_path_len(0), b"", payload)
        try:
            self._remember(out.packet_hash())   # de-dupe the repeater's echo of our ack
        except Exception:
            pass
        self._enqueue_tx(out.to_bytes())

    def _handle_path(self, pkt):
        """A PATH-return addressed to us may carry the ACK for a DM we sent -> mark delivered."""
        self_hash = self.node_id()
        if self_hash is None or len(pkt.payload) < 2:
            return False
        if pkt.payload[0] != (self_hash & 0xFF):
            return False
        candidates = self._contact_candidates(pkt.payload[1])
        if not candidates:
            return False
        try:
            dec = meshcore_dm.decode_path(pkt.payload, self_hash, candidates)
        except Exception as e:
            print("MeshCore: path decode error:", repr(e))
            return False
        if not dec:
            return False
        if dec.get("ack_hash"):
            self._mark_delivered(dec["ack_hash"])
        return True

    def _handle_ack(self, pkt):
        """A bare ACK packet (direct-routed) -> mark the matching sent DM delivered."""
        ack = meshcore_dm.decode_ack(pkt.payload)
        if ack is None:
            return False
        return self._mark_delivered(ack)

    def _register_pending(self, ack_hex, pubkey_hex, msg):
        self._pending_acks[ack_hex] = (pubkey_hex, msg)
        self._pending_order.append(ack_hex)
        while len(self._pending_order) > 32:
            self._pending_acks.pop(self._pending_order.pop(0), None)

    def _mark_delivered(self, ack4):
        key = ack4.hex() if hasattr(ack4, "hex") else ack4
        entry = self._pending_acks.pop(key, None)
        if not entry:
            return False
        try:
            self._pending_order.remove(key)
        except ValueError:
            pass
        pub_hex, msg = entry
        msg["delivered"] = True
        print("MeshCore: DM delivered (ack %s)" % key)
        self._save_history(pub_hex)
        self._notify("dm", (pub_hex, msg))
        return True

    def send_dm(self, pubkey_hex, text):
        """Encrypt + flood a direct text message to a contact. Returns (ok, err)."""
        text = (text or "").strip()
        if not text:
            return (False, "empty message")
        pub, prv = self.get_identity()
        if pub is None:
            return (False, "no identity -- generate one first")
        contact = self._contacts.get(pubkey_hex)
        if contact is None:
            return (False, "not a contact -- add them first")
        secret = self._node_secret(contact)
        if secret is None:
            return (False, "no shared secret")
        try:
            import binascii
            import time
            ts = int(time.time())
            dst_hash = binascii.unhexlify(pubkey_hex.encode())[0]
            payload, expected_ack = meshcore_dm.encode_dm(secret, pub, dst_hash, text, ts)
        except Exception as e:
            print("MeshCore: dm encode error:", repr(e))
            return (False, str(e))
        pkt = MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_TXT_MSG),
                             encode_path_len(0), b"", payload)
        try:
            self._remember(pkt.packet_hash())   # de-dupe the repeater's echo of our own DM
        except Exception:
            pass
        self._enqueue_tx(pkt.to_bytes())   # worker transmits in the next RX gap
        msg = {"ts": ts, "sender": self.nickname(), "text": text, "rssi": None,
               "incoming": False, "ack": expected_ack.hex(), "delivered": False}
        self._add_dm(pubkey_hex, msg)
        self._register_pending(expected_ack.hex(), pubkey_hex, msg)  # match a returning ACK
        self._notify("dm", (pubkey_hex, msg))
        return (True, None)

    def _add_dm(self, pubkey_hex, msg):
        lst = self._dm_messages.setdefault(pubkey_hex, [])
        lst.append(msg)
        if len(lst) > MAX_MESSAGES:
            del lst[0]
        self._save_history(pubkey_hex)   # persist per-contact chat history

    def get_dm_messages(self, pubkey_hex):
        return list(self._dm_messages.get(pubkey_hex, []))

    # --- contacts (persisted) ---------------------------------------------- #
    def get_contacts(self):
        """The saved contact list -- the ONLY nodes we can chat with."""
        return sorted(self._contacts.values(),
                      key=lambda c: (c.get("seq", 0), c.get("name") or ""), reverse=True)

    def get_contact(self, pubkey_hex):
        return self._contacts.get(pubkey_hex)

    def is_contact(self, pubkey_hex):
        return pubkey_hex in self._contacts

    def get_learned_companions(self):
        """Companions heard via advert this session (RAM only). Add one -> it becomes a
        persisted contact you can chat with."""
        return sorted(self._nodes.values(), key=lambda n: n.get("seq", 0), reverse=True)

    def add_contact(self, pubkey_hex, name=None, node_type=ADV_TYPE_CHAT):
        """Add a learned companion (or explicit pubkey) to the saved contact list."""
        if not pubkey_hex or len(pubkey_hex) != 64:
            return (False, "invalid public key")
        if pubkey_hex in self._contacts:
            return (True, None)  # already a contact
        node = self._nodes.get(pubkey_hex, {})
        if not name:
            name = node.get("name") or pubkey_hex[0:2]
        self._contacts[pubkey_hex] = {
            "pubkey": pubkey_hex,
            "id": pubkey_hex[0:2],
            "name": name,
            "type": node_type,
            "type_name": "chat",
            "secret": None,
            "rssi": node.get("rssi"),
            "seq": node.get("seq", 0),
        }
        self._dm_messages.setdefault(pubkey_hex, [])
        self._save_contacts()
        self._notify("contacts", None)
        return (True, None)

    def remove_contact(self, pubkey_hex):
        if pubkey_hex not in self._contacts:
            return False
        del self._contacts[pubkey_hex]
        self._dm_messages.pop(pubkey_hex, None)
        self._save_contacts()
        self._delete_history(pubkey_hex)   # drop the stored chat history too
        self._notify("contacts", None)
        return True

    # --- contact / history persistence (SharedPreferences) ----------------- #
    def _load_contacts(self):
        try:
            from mpos import SharedPreferences
            p = SharedPreferences(NICKNAME_PREFS)
            saved = p.get_dict("contacts", {}) or {}
            histories = p.get_dict("dm_history", {}) or {}
        except Exception as e:
            print("MeshCore: load contacts error:", repr(e))
            saved, histories = {}, {}
        for pub_hex, entry in saved.items():
            try:
                self._contacts[pub_hex] = {
                    "pubkey": pub_hex,
                    "id": pub_hex[0:2],
                    "name": entry.get("name") or pub_hex[0:2],
                    "type": entry.get("type", ADV_TYPE_CHAT),
                    "type_name": "chat",
                    "secret": None,
                    "rssi": None,
                    "seq": 0,
                }
                self._dm_messages[pub_hex] = list(histories.get(pub_hex, []))
            except Exception as e:
                print("MeshCore: skipping bad contact %r: %s" % (pub_hex, e))

    def _save_contacts(self):
        try:
            from mpos import SharedPreferences
            data = {h: {"name": c["name"], "type": c.get("type", ADV_TYPE_CHAT)}
                    for h, c in self._contacts.items()}
            ed = SharedPreferences(NICKNAME_PREFS).edit()
            ed.put_dict("contacts", data)
            ed.commit()
        except Exception as e:
            print("MeshCore: save contacts error:", repr(e))

    def _save_history(self, pubkey_hex):
        if pubkey_hex not in self._contacts:
            return  # only contacts' history is stored
        try:
            from mpos import SharedPreferences
            ed = SharedPreferences(NICKNAME_PREFS).edit()
            ed.put_dict_item("dm_history", pubkey_hex, self._dm_messages.get(pubkey_hex, []))
            ed.commit()
        except Exception as e:
            print("MeshCore: save history error:", repr(e))

    def _delete_history(self, pubkey_hex):
        try:
            from mpos import SharedPreferences
            ed = SharedPreferences(NICKNAME_PREFS).edit()
            ed.remove_dict_item("dm_history", pubkey_hex)
            ed.commit()
        except Exception as e:
            print("MeshCore: delete history error:", repr(e))

    def _post_dm_notification(self, pubkey_hex, name, msg):
        """Notify for an incoming DM unless the app is foreground (mirrors channels)."""
        try:
            from mpos import Notification, NotificationManager, get_foreground_app
        except Exception:
            return
        try:
            if get_foreground_app() == MESHCORE_APP:
                return
            intent = None
            try:
                from mpos import Intent
                from meshcore import DMChatActivity
                intent = Intent(activity_class=DMChatActivity, extras={"pubkey": pubkey_hex})
            except Exception:
                intent = None
            text = msg.get("text", "")
            if len(text) > 80:
                text = text[:77] + "..."
            NotificationManager.notify(Notification(
                notification_id="meshcore-dm:%s" % pubkey_hex,
                title="DM %s" % name,
                text=text,
                intent=intent,
                app_fullname=MESHCORE_APP,
            ))
        except Exception as e:
            print("MeshCore: dm notify error:", repr(e))

    def _post_notification(self, channel_name, msg):
        """Raise a system notification for an incoming message, unless the MeshCore app
        is currently in the foreground.  This is what surfaces messages received in the
        background (app closed / on the home screen) so they aren't missed."""
        try:
            from mpos import Notification, NotificationManager, get_foreground_app
        except Exception as e:
            print("MeshCore: notifications unavailable:", repr(e))
            return
        try:
            if get_foreground_app() == MESHCORE_APP:
                return  # user is already in the app; the chat view updates live
            # Best-effort tap-to-open the channel; falls back to no intent if the UI
            # module isn't importable yet (e.g. app never opened this session).
            intent = None
            try:
                from mpos import Intent
                from meshcore import ChannelChatActivity
                intent = Intent(activity_class=ChannelChatActivity,
                                extras={"channel": channel_name})
            except Exception:
                intent = None
            text = "%s: %s" % (msg.get("sender", "?"), msg.get("text", ""))
            if len(text) > 80:
                text = text[:77] + "..."
            NotificationManager.notify(Notification(
                notification_id="meshcore:%s" % channel_name,
                title="# %s" % channel_name,
                text=text,
                intent=intent,
                app_fullname=MESHCORE_APP,
            ))
        except Exception as e:
            print("MeshCore: notify error:", repr(e))

    def _log(self, record):
        self._packets.insert(0, record)
        if len(self._packets) > MAX_PACKETS:
            self._packets.pop()
        self._notify("packet", record)

    def _add_message(self, channel_name, msg):
        lst = self._messages.setdefault(channel_name, [])
        lst.append(msg)
        if len(lst) > MAX_MESSAGES:
            del lst[0]

    # --- send --------------------------------------------------------------- #
    def send_group_text(self, channel_name, text):
        ch = self.get_channel(channel_name)
        if ch is None or not text:
            return False
        try:
            import time
            ts = int(time.time())
        except Exception:
            ts = 0
        payload = encode_group_text(ch, self.nickname(), text, ts)
        pkt = MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_GRP_TXT),
                             encode_path_len(0), b"", payload)
        # Remember our own packet so the repeater's echo of it is de-duplicated.
        try:
            self._remember(pkt.packet_hash())
        except Exception:
            pass
        self._enqueue_tx(pkt.to_bytes())   # worker transmits in the next RX gap
        # reflect our own message locally right away (the actual TX happens shortly)
        msg = {"ts": ts, "sender": self.nickname(), "text": text, "rssi": None, "incoming": False}
        self._add_message(channel_name, msg)
        self._notify("message", (channel_name, msg))
        return True

    def _time_on_air_ms(self, payload_len):
        """LoRa time-on-air (ms) for our fixed PHY: SF8, BW 62.5 kHz, CR 4/8, 16-symbol
        preamble, explicit header, CRC on.  Used to blind-wait a TX to completion without
        touching SPI (see _transmit)."""
        sf = 8
        bw = 62500.0
        cr = 4          # coding rate 4/(4+cr) -> 4/8
        n_pre = 16
        crc = 1
        ih = 0          # explicit header
        de = 0          # low-data-rate optimise off (T_sym < 16 ms)
        t_sym = (1 << sf) / bw
        t_pre = (n_pre + 4.25) * t_sym
        num = 8 * payload_len - 4 * sf + 28 + 16 * crc - 20 * ih
        den = 4 * (sf - 2 * de)
        n_payload = 8 + max(((num + den - 1) // den) * (cr + 4), 0)  # ceil(num/den)*(cr+4)
        return int((t_pre + n_payload * t_sym) * 1000)

    def _transmit(self, raw):
        if simulation_mode:
            print("MeshCoreManager: SIM TX %s" % raw.hex())
            return True
        if not self._radio_ready or self._radio is None:
            # Guard: send() needs the radio in non-blocking mode (setBlockingCallback ran);
            # transmitting before bring-up completes fails with "no attribute 'blocking'".
            print("MeshCoreManager: cannot TX, radio not ready")
            return False
        from drivers.lora.sx1262 import SX1262
        import time
        ok = False
        self._radio_lock.acquire()
        try:
            # RF switch: GPIO46 HIGH = RX path, LOW = TX path. Route the antenna to the
            # PA for the duration of the transmit, or nothing radiates.
            if self._rf_sw is not None:
                self._rf_sw.value(0)
            _, result = self._radio.send(raw)   # non-blocking: returns immediately
            print("MeshCoreManager: TX result %s" % SX1262.STATUS[result])
            # Wait out the airtime with NO SPI whatsoever. send() is non-blocking, so we must
            # wait before re-arming RX -- but polling getIrqStatus() during TX collides with
            # the LCD's DMA on the shared SPI bus 2 and WEDGES the radio (GetStatus -> 0x00).
            # So we blind-sleep the computed time-on-air (a fixed 900 ms was too short for long
            # packets like adverts, which then re-armed RX mid-TX -> standby/deaf).
            time.sleep_ms(self._time_on_air_ms(len(raw)) + 120)
            ok = (result == 0)
        except Exception as e:
            print("MeshCoreManager: TX exception:", repr(e))
        finally:
            # Antenna back to the RX path, clear any latched IRQ, then re-arm receive.
            if self._rf_sw is not None:
                self._rf_sw.value(1)
            try:
                self._radio.clearIrqStatus()
            except Exception:
                pass
            try:
                self._radio.startReceive()
            except Exception:
                pass
            self._radio_lock.release()
        return ok

    # --- accessors (UI) ----------------------------------------------------- #
    def get_nodes(self):
        # most-recently-heard first
        return sorted(self._nodes.values(), key=lambda n: n.get("seq", 0), reverse=True)

    def get_node(self, pubkey_hex):
        return self._nodes.get(pubkey_hex)

    def get_channels(self):
        return list(self._channels)

    def get_channel_names(self):
        return [c.name for c in self._channels]

    def get_channel(self, name):
        for c in self._channels:
            if c.name == name:
                return c
        return None

    def get_messages(self, channel_name):
        return list(self._messages.get(channel_name, []))

    def get_packets(self):
        return list(self._packets)

    def clear(self):
        self._packets = []
        self._count = 0

    # --- subscribers -------------------------------------------------------- #
    def add_subscriber(self, cb):
        if cb not in self._subscribers:
            self._subscribers.append(cb)

    def remove_subscriber(self, cb):
        try:
            self._subscribers.remove(cb)
        except ValueError:
            pass

    def _notify(self, event, data):
        for cb in list(self._subscribers):
            try:
                cb(event, data)
            except Exception as e:
                print("MeshCoreManager: subscriber error:", repr(e))

    # --- simulation (desktop) ---------------------------------------------- #
    def _start_simulation(self):
        if self._sim_started:
            return
        self._sim_started = True
        try:
            import _thread
            _thread.start_new_thread(self._sim_loop, ())
        except Exception:
            self._sim_feed()

    def _sim_loop(self):
        import time
        time.sleep(1)
        self._sim_feed()

    def _sim_feed(self):
        import struct
        # a chat node advert + a repeater advert + a public message
        def advert(pk0, flags, name):
            pk = bytes([pk0]) + bytes(range(31))
            return pk + struct.pack("<I", 0x662d5a10) + b"\x00" * 64 + bytes([flags]) + name
        from meshcore_advert import ADV_TYPE_CHAT, ADV_TYPE_REPEATER, ADV_NAME_MASK
        self._ingest(MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT),
                                    encode_path_len(0), b"",
                                    advert(0xa1, ADV_TYPE_CHAT | ADV_NAME_MASK, b"SimChat")).to_bytes(),
                     rssi=-80, snr=8.0)
        self._ingest(MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT),
                                    encode_path_len(0), b"",
                                    advert(0xb2, ADV_TYPE_REPEATER | ADV_NAME_MASK, b"RoofRepeater")).to_bytes(),
                     rssi=-95, snr=5.5)
        grp = encode_group_text(PUBLIC_CHANNEL, "SimChat", "hello from sim", 0x662d5a10)
        self._ingest(MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_GRP_TXT),
                                    encode_path_len(0), b"", grp).to_bytes(),
                     rssi=-80, snr=8.0)
