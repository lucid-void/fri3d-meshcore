# MeshCore client UI.
#
# Thin views on top of MeshCoreManager, which owns the radio and receives/sends in the
# background (started at boot by MeshCoreBootService when selected, or on demand here).
#
#   MeshCoreHome      -- launcher activity, gated by Settings > LoRa App. Tabview:
#                          Channels (tap chat, long-press remove), Companions (learned this
#                          session; tap to add as contact), Contacts (persisted; tap chat,
#                          long-press remove), Me.
#   ChannelChatActivity -- per public #channel chat: message list + input + send.
#   DMChatActivity      -- per-contact 1:1 encrypted chat (X25519 + AES-128 + HMAC).
#
# One LoRa app owns the shared SX1262 at a time, so this mutually excludes LoRa Chat.
# Companions are learned (UNVERIFIED -- advert signatures aren't checked) and kept in RAM;
# only once you ADD one as a contact can you chat, and the contact + history are persisted.
# Repeaters/rooms/sensors are ignored -- the badge only deals with companions.

import lvgl as lv

from mpos import (Activity, Intent, MposKeyboard, InputActivity, DisplayMetrics)

from meshcore_manager import MeshCoreManager

# Buttons default to the theme's accent colour, and the focus ring is that same colour --
# so the selection is invisible on them. Give buttons a dark neutral fill (distinct from the
# screen background) so the accent-coloured focus ring reads clearly.
_BTN_BG = 0x39404B
_BADGE_BG = 0xC0392B


def _dark(btn):
    btn.set_style_bg_color(lv.color_hex(_BTN_BG), 0)
    return btn


class MeshCoreHome(Activity):

    def __init__(self):
        super().__init__()
        self.manager = None
        self.nodes_list = None
        self.channels_list = None
        self.dms_list = None
        self.name_label = None
        self.identity_label = None
        self.gen_id_btn = None
        self.backup_id_btn = None
        self.advert_btn = None
        self.share_qr_btn = None
        self.service_switch = None
        self.diag_label = None
        self._diag_timer = None
        self._keygen_busy = False       # guard: one keygen thread at a time
        self._advert_busy = False       # guard: one advertise thread at a time
        self._sub = None

    def onCreate(self):
        screen = lv.obj()
        tabview = lv.tabview(screen)
        tabview.set_tab_bar_size(36)

        self._build_channels_tab(tabview.add_tab("Channels"))
        self._build_nodes_tab(tabview.add_tab("Companions"))
        self._build_dms_tab(tabview.add_tab("Contacts"))
        self._build_me_tab(tabview.add_tab(lv.SYMBOL.SETTINGS))   # "Me" -> a gear icon

        # make the settings/gear tab narrow (it's just an icon) so the others get more room
        try:
            bar = tabview.get_tab_bar()
            gear = bar.get_child(3)
            gear.set_flex_grow(0)
            gear.set_width(44)
        except Exception as e:
            print("MeshCoreHome: tab-bar sizing skipped:", repr(e))

        self.setContentView(screen)

    # --- shared row + confirm helpers -------------------------------------- #
    def _rows_container(self, tab):
        """Style a tab as a flex column and return a scrollable child container for rows."""
        tab.set_flex_flow(lv.FLEX_FLOW.COLUMN)
        tab.set_style_pad_all(6, 0)
        tab.set_style_pad_gap(6, 0)
        c = lv.obj(tab)
        c.set_width(lv.pct(100))
        c.set_flex_grow(1)
        c.set_flex_flow(lv.FLEX_FLOW.COLUMN)
        c.set_style_pad_all(0, 0)
        c.set_style_pad_gap(4, 0)
        c.set_style_border_width(0, 0)
        c.set_style_bg_opa(lv.OPA.TRANSP, 0)
        return c

    def _list_row(self, parent, text, on_open, on_delete=None, badge=0):
        """A row: name button (tap = open), an unread badge, and an optional red trash button."""
        row = lv.obj(parent)
        row.set_width(lv.pct(100))
        row.set_height(lv.SIZE_CONTENT)
        row.set_flex_flow(lv.FLEX_FLOW.ROW)
        row.set_flex_align(lv.FLEX_ALIGN.SPACE_BETWEEN, lv.FLEX_ALIGN.CENTER, lv.FLEX_ALIGN.CENTER)
        row.set_style_pad_all(0, 0)
        row.set_style_pad_gap(6, 0)
        row.set_style_border_width(0, 0)
        row.set_style_bg_opa(lv.OPA.TRANSP, 0)
        nb = _dark(lv.button(row))
        nb.set_flex_grow(1)
        nb.add_event_cb(lambda e: on_open(), lv.EVENT.CLICKED, None)
        nl = lv.label(nb)
        nl.set_text(text)
        nl.set_long_mode(lv.label.LONG_MODE.WRAP)
        nl.set_width(lv.pct(100))
        if badge:
            bl = lv.label(row)
            bl.set_text(str(badge) if badge < 100 else "99+")
            bl.set_style_bg_color(lv.color_hex(_BADGE_BG), 0)
            bl.set_style_bg_opa(lv.OPA.COVER, 0)
            bl.set_style_text_color(lv.color_hex(0xFFFFFF), 0)
            bl.set_style_pad_all(5, 0)
            bl.set_style_radius(12, 0)
        if on_delete is not None:
            db = lv.button(row)
            db.set_style_bg_color(lv.color_hex(0xC0392B), 0)   # red = destructive
            db.add_event_cb(lambda e: on_delete(), lv.EVENT.CLICKED, None)
            lv.label(db).set_text(lv.SYMBOL.TRASH)
        return row

    @staticmethod
    def _hint(parent, text):
        lbl = lv.label(parent)
        lbl.set_text(text)
        lbl.set_long_mode(lv.label.LONG_MODE.WRAP)
        lbl.set_width(lv.pct(100))

    @staticmethod
    def _close_mbox(mbox):
        try:
            mbox.close()
        except Exception:
            pass

    def _confirm(self, text, on_yes, yes="OK", no="Cancel"):
        mbox = lv.msgbox()
        mbox.set_width(DisplayMetrics.pct_of_width(80))
        mbox.add_text(text)
        yb = mbox.add_footer_button(yes)
        yb.add_event_cb(lambda e: (self._close_mbox(mbox), on_yes()), lv.EVENT.CLICKED, None)
        nb = mbox.add_footer_button(no)
        nb.add_event_cb(lambda e: self._close_mbox(mbox), lv.EVENT.CLICKED, None)

    # --- Channels tab ------------------------------------------------------- #
    def _build_channels_tab(self, tab):
        add_btn = _dark(lv.button(tab))
        add_btn.set_width(lv.pct(100))
        add_btn.add_event_cb(lambda e: self._prompt_add_channel(), lv.EVENT.CLICKED, None)
        lv.label(add_btn).set_text(lv.SYMBOL.PLUS + " New channel")
        self.channels_list = self._rows_container(tab)

    def _refresh_channels(self):
        if self.channels_list is None:
            return
        self.channels_list.clean()
        m = MeshCoreManager.get_instance()
        for name in m.get_channel_names():
            on_del = None if name == "Public" else (lambda n=name: self._ask_delete_channel(n))
            self._list_row(self.channels_list, "# " + name,
                           lambda n=name: self._open_channel(n), on_del,
                           badge=m.get_unread(name))

    def _ask_delete_channel(self, name):
        self._confirm("Delete channel #%s?" % name,
                      lambda: self._do_remove_channel(name), yes="Delete")

    def _do_remove_channel(self, name):
        MeshCoreManager.get_instance().remove_channel(name)
        lv.async_call(lambda _: self._refresh_channels(), None)

    def _open_channel(self, name):
        self.startActivity(Intent(activity_class=ChannelChatActivity, extras={"channel": name}))

    def _prompt_add_channel(self):
        setting = {"key": "channel", "title": "Add channel", "ui": "textarea",
                   "placeholder": "name = public #name   (name|base64key = private)"}
        self.startActivityForResult(
            Intent(activity_class=InputActivity, extras={"setting": setting}),
            self._on_add_channel)

    def _on_add_channel(self, result):
        if not result or not result.get("result_code"):
            return
        value = result.get("data", {}).get("value", "").strip()
        if not value:
            return
        # "name|psk" joins an existing channel; a bare "name" creates a new one.
        if "|" in value:
            name, psk = value.split("|", 1)
        else:
            name, psk = value, ""
        ok, err = MeshCoreManager.get_instance().add_channel(name.strip(), psk.strip())
        print("MeshCore: add_channel(%r) -> ok=%s err=%s" % (name.strip(), ok, err))
        lv.async_call(lambda _: self._refresh_channels(), None)

    # --- Companions tab (learned nodes; tap to add as contact) -------------- #
    def _build_nodes_tab(self, tab):
        self.nodes_list = lv.list(tab)
        self.nodes_list.set_size(lv.pct(100), lv.pct(100))

    def _refresh_nodes(self):
        if self.nodes_list is None:
            return
        self.nodes_list.clean()
        m = MeshCoreManager.get_instance()
        companions = m.get_learned_companions()
        if not companions:
            self.nodes_list.add_text("No companions heard yet. Nearby chat nodes show up "
                                     "here; tap one to add it as a contact.")
            return
        self.nodes_list.add_text("Tap a companion to add it as a contact")
        for n in companions:
            name = n.get("name") or ("id " + n.get("id", "??"))
            pub = n.get("pubkey")
            rssi = n.get("rssi")
            is_c = m.is_contact(pub) if pub else False
            mark = (" " + lv.SYMBOL.OK) if is_c else ""
            label = "%s%s  %s%s" % (
                name, mark,
                ("%sdBm  " % rssi) if rssi is not None else "",
                n.get("id", ""))
            btn = self.nodes_list.add_button(None, label)
            if pub:
                btn.add_event_cb(lambda e, p=pub, nm=name: self._companion_tapped(p, nm),
                                 lv.EVENT.CLICKED, None)

    def _companion_tapped(self, pubkey_hex, name):
        # add to contacts if needed, then open the 1:1 chat
        m = MeshCoreManager.get_instance()
        if not m.is_contact(pubkey_hex):
            ok, err = m.add_contact(pubkey_hex, name)
            if not ok:
                print("MeshCore: add_contact failed:", err)
                return
        self._open_dm(pubkey_hex, name)

    # --- Contacts tab ------------------------------------------------------- #
    def _build_dms_tab(self, tab):
        self.dms_list = self._rows_container(tab)

    def _refresh_dms(self):
        if self.dms_list is None:
            return
        self.dms_list.clean()
        m = MeshCoreManager.get_instance()
        if not m.has_identity():
            self._hint(self.dms_list, "Generate an identity (" + lv.SYMBOL.SETTINGS +
                       " tab) to use DMs")
            return
        contacts = m.get_contacts()
        if not contacts:
            self._hint(self.dms_list, "No contacts yet -- add a companion from the "
                       "Companions tab")
            return
        for c in contacts:
            pub = c.get("pubkey")
            if not pub:
                continue
            name = c.get("name") or ("id " + c.get("id", "??"))
            self._list_row(self.dms_list, "%s  %s" % (name, c.get("id", "")),
                           lambda p=pub, nm=name: self._open_dm(p, nm),
                           lambda p=pub, nm=name: self._ask_delete_contact(p, nm),
                           badge=m.get_unread(pub))

    def _ask_delete_contact(self, pubkey_hex, name):
        self._confirm("Remove contact %s?\n(this also deletes the chat history)" % name,
                      lambda: self._do_remove_contact(pubkey_hex), yes="Delete")

    def _do_remove_contact(self, pubkey_hex):
        MeshCoreManager.get_instance().remove_contact(pubkey_hex)
        lv.async_call(lambda _: self._refresh_dms(), None)

    def _open_dm(self, pubkey_hex, name):
        self.startActivity(Intent(activity_class=DMChatActivity,
                                  extras={"pubkey": pubkey_hex, "name": name}))

    def _build_me_tab(self, tab):
        tab.set_flex_flow(lv.FLEX_FLOW.COLUMN)
        tab.set_style_pad_all(12, 0)
        tab.set_style_pad_gap(10, 0)

        # --- background radio service toggle (the app's on/off switch) ---
        svc_row = lv.obj(tab)
        svc_row.set_width(lv.pct(100))
        svc_row.set_height(lv.SIZE_CONTENT)
        svc_row.set_flex_flow(lv.FLEX_FLOW.ROW)
        svc_row.set_flex_align(lv.FLEX_ALIGN.SPACE_BETWEEN, lv.FLEX_ALIGN.CENTER, lv.FLEX_ALIGN.CENTER)
        svc_row.set_style_pad_all(0, 0)
        svc_row.set_style_border_width(0, 0)
        svc_lbl = lv.label(svc_row)
        svc_lbl.set_text("Radio service")
        svc_lbl.set_style_text_font(lv.font_montserrat_16, lv.PART.MAIN)
        self.service_switch = lv.switch(svc_row)
        if MeshCoreManager.get_instance().is_service_enabled():
            self.service_switch.add_state(lv.STATE.CHECKED)
        self.service_switch.add_event_cb(self._on_service_toggle, lv.EVENT.VALUE_CHANGED, None)

        svc_note = lv.label(tab)
        svc_note.set_text("On = run the LoRa node (receive in the background + send). "
                          "Off = radio idle. You'll be asked to confirm. Turn off before "
                          "using the LoRa Chat app.")
        svc_note.set_long_mode(lv.label.LONG_MODE.WRAP)
        svc_note.set_width(lv.pct(100))
        svc_note.set_style_text_font(lv.font_montserrat_12, lv.PART.MAIN)

        # --- live radio diagnostics (updated by a timer while this screen is open) ---
        diag_box = lv.obj(tab)
        diag_box.set_width(lv.pct(100))
        diag_box.set_height(lv.SIZE_CONTENT)
        diag_box.set_style_pad_all(8, 0)
        self.diag_label = lv.label(diag_box)
        self.diag_label.set_text("Radio: ...")
        self.diag_label.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.diag_label.set_width(lv.pct(100))
        self.diag_label.set_style_text_font(lv.font_montserrat_14, lv.PART.MAIN)

        self.name_label = lv.label(tab)
        self.name_label.set_text("Name: " + MeshCoreManager.get_instance().nickname())
        self.name_label.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.name_label.set_width(lv.pct(100))

        name_btn = _dark(lv.button(tab))
        name_btn.add_event_cb(lambda e: self._prompt_name(), lv.EVENT.CLICKED, None)
        lv.label(name_btn).set_text("Edit name")

        # --- identity ---
        self.identity_label = lv.label(tab)
        self.identity_label.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.identity_label.set_width(lv.pct(100))

        self.gen_id_btn = _dark(lv.button(tab))
        self.gen_id_btn.add_event_cb(lambda e: self._generate_identity(), lv.EVENT.CLICKED, None)
        lv.label(self.gen_id_btn).set_text("Generate identity (slow)")

        self.backup_id_btn = _dark(lv.button(tab))
        self.backup_id_btn.add_event_cb(lambda e: self._backup_identity(), lv.EVENT.CLICKED, None)
        lv.label(self.backup_id_btn).set_text("Backup keys to SD")

        self.advert_btn = _dark(lv.button(tab))
        self.advert_btn.add_event_cb(lambda e: self._advertise_now(), lv.EVENT.CLICKED, None)
        lv.label(self.advert_btn).set_text("Advertise now")

        self.share_qr_btn = _dark(lv.button(tab))
        self.share_qr_btn.add_event_cb(lambda e: self._share_contact(), lv.EVENT.CLICKED, None)
        lv.label(self.share_qr_btn).set_text("Share my contact (QR)")

        restart_btn = _dark(lv.button(tab))
        restart_btn.add_event_cb(lambda e: self._restart_radio(), lv.EVENT.CLICKED, None)
        lv.label(restart_btn).set_text("Restart radio")

        note = lv.label(tab)
        note.set_text("Your name is the sender on public # channels. An identity "
                      "(Ed25519 keypair) is needed to advertise and for DMs.")
        note.set_long_mode(lv.label.LONG_MODE.WRAP)
        note.set_width(lv.pct(100))

        self._refresh_identity()

    def _refresh_identity(self):
        if self.identity_label is None:
            return
        from binascii import hexlify
        m = MeshCoreManager.get_instance()
        pub, _ = m.get_identity()
        if pub:
            self.identity_label.set_text(
                "Node ID: %02x\nKey: %s..." % (pub[0], hexlify(pub).decode()[:16]))
            self.gen_id_btn.add_flag(lv.obj.FLAG.HIDDEN)
            self.backup_id_btn.remove_flag(lv.obj.FLAG.HIDDEN)
            self.advert_btn.remove_flag(lv.obj.FLAG.HIDDEN)
            self.share_qr_btn.remove_flag(lv.obj.FLAG.HIDDEN)
        else:
            self.identity_label.set_text("Identity: not generated")
            self.gen_id_btn.remove_flag(lv.obj.FLAG.HIDDEN)
            self.backup_id_btn.add_flag(lv.obj.FLAG.HIDDEN)
            self.advert_btn.add_flag(lv.obj.FLAG.HIDDEN)
            self.share_qr_btn.add_flag(lv.obj.FLAG.HIDDEN)

    def _generate_identity(self):
        # keygen is slow (pure-Python) -> run off the UI thread; ignore re-taps while busy
        if self._keygen_busy:
            return
        self._keygen_busy = True
        self.update_ui_threadsafe_if_foreground(
            lambda: self.identity_label.set_text("Generating identity...\n(may take a while)"))
        try:
            import _thread
            from mpos import TaskManager
            _thread.stack_size(TaskManager.good_stack_size())
            _thread.start_new_thread(self._generate_identity_thread, ())
        except Exception as e:
            print("MeshCoreHome: could not start keygen thread:", repr(e))
            self._generate_identity_thread()

    def _generate_identity_thread(self):
        try:
            MeshCoreManager.get_instance().generate_identity()
        finally:
            self._keygen_busy = False
        self.update_ui_threadsafe_if_foreground(self._refresh_identity)

    def _backup_identity(self):
        ok, info = MeshCoreManager.get_instance().backup_identity_to_sd()
        msg = ("Backed up to %s" % info) if ok else ("Backup failed: %s" % info)
        print("MeshCoreHome: backup ->", msg)
        self.update_ui_threadsafe_if_foreground(
            lambda: self.identity_label.set_text(self.identity_label.get_text() + "\n" + msg))

    def _advertise_now(self):
        # signing is slow -> run off the UI thread; ignore re-taps while busy
        if self._advert_busy:
            return
        self._advert_busy = True
        self.update_ui_threadsafe_if_foreground(
            lambda: self.identity_label.set_text(self.identity_label.get_text() + "\nAdvertising..."))
        try:
            import _thread
            from mpos import TaskManager
            _thread.stack_size(TaskManager.good_stack_size())
            _thread.start_new_thread(self._advertise_thread, ())
        except Exception:
            self._advertise_thread()

    def _advertise_thread(self):
        try:
            ok, err = MeshCoreManager.get_instance().advertise()
        finally:
            self._advert_busy = False
        line = "Advertised." if ok else ("Advert failed: %s" % err)
        self.update_ui_threadsafe_if_foreground(
            lambda: (self._refresh_identity(),
                     self.identity_label.set_text(self.identity_label.get_text() + "\n" + line)))

    def _share_contact(self):
        m = MeshCoreManager.get_instance()
        uri = m.contact_uri()
        if not uri:
            return
        self.startActivity(Intent(activity_class=ShareQRActivity, extras={
            "uri": uri,
            "title": "Scan to add " + m.nickname(),
            "note": "Scan in the MeshCore mobile app\n(Add Contact) to message me."}))

    def _prompt_name(self):
        current = MeshCoreManager.get_instance().nickname()
        setting = {"key": "name", "title": "Set name", "ui": "textarea",
                   "placeholder": current}
        self.startActivityForResult(
            Intent(activity_class=InputActivity, extras={"setting": setting, "value": current}),
            self._on_name_result)

    def _on_name_result(self, result):
        if not result or not result.get("result_code"):
            return
        name = result.get("data", {}).get("value", "").strip()
        if name and MeshCoreManager.get_instance().set_nickname(name):
            lv.async_call(lambda _: self.name_label.set_text("Name: " + name), None)

    def _restart_radio(self):
        print("MeshCoreHome: restart radio requested")
        MeshCoreManager.get_instance().restart()

    def _on_service_toggle(self, event):
        # a switch is easy to brush by accident -> require a confirm; revert until confirmed
        m = MeshCoreManager.get_instance()
        want = self.service_switch.has_state(lv.STATE.CHECKED)
        if want == m.is_service_enabled():
            return  # programmatic sync, not a real user toggle
        self._sync_service_switch(m.is_service_enabled())   # snap back until confirmed
        self._confirm("Turn the radio service ON?" if want else "Turn the radio service OFF?",
                      lambda: m.set_service_enabled(want), yes="Yes", no="No")

    # --- live diagnostics --------------------------------------------------- #
    @staticmethod
    def _fmt_status(s):
        if not s["enabled"]:
            return "Radio service: OFF"
        if not s["ready"]:
            return "Radio: recovering..." if s["recovering"] else "Radio: starting..."
        state = {"listening": "listening (RX)", "transmitting": "transmitting",
                 "standby": "idle (standby)", "tuning": "tuning",
                 "stuck": "STUCK -- power-cycle the badge"}.get(s["mode"], "starting...")
        lines = ["Radio: " + state]
        rx = s["last_rx_ms"]
        seen = ("  (%ds ago)" % (rx // 1000)) if (rx is not None and rx < 3600000) else ""
        lines.append("Received %d pkts%s" % (s["rx_count"], seen))
        lines.append("Sent %d" % s["tx_count"] + ("  (%d queued)" % s["tx_pending"] if s["tx_pending"] else ""))
        if s["reinits"]:
            lines.append("Auto-recoveries: %d" % s["reinits"])
        lines.append("Companions %d  Contacts %d" % (s["nodes"], s["contacts"]))
        return "\n".join(lines)

    def _diag_tick(self):
        if self.diag_label is None:
            return
        try:
            self.diag_label.set_text(self._fmt_status(MeshCoreManager.get_instance().radio_status()))
        except Exception as e:
            print("MeshCoreHome: diag tick error:", repr(e))

    # --- lifecycle ---------------------------------------------------------- #
    def onResume(self, screen):
        super().onResume(screen)
        self.manager = MeshCoreManager.get_instance()
        # only run the radio when the service is enabled (the Me-tab toggle is the control)
        if self.manager.is_service_enabled() and not self.manager.is_running():
            print("MeshCoreHome: service enabled, starting manager")
            self.manager.start()
        self._refresh_channels()
        self._refresh_nodes()
        self._refresh_dms()
        self._sub = lambda ev, data: self._on_event(ev, data)
        self.manager.add_subscriber(self._sub)
        # live radio diagnostics on the Me tab, refreshed while this screen is foreground
        self._diag_tick()
        if self._diag_timer is None:
            self._diag_timer = lv.timer_create(lambda t: self._diag_tick(), 2000, None)

    def onPause(self, screen):
        super().onPause(screen)
        if self.manager is not None and self._sub is not None:
            self.manager.remove_subscriber(self._sub)
            self._sub = None
        if self._diag_timer is not None:
            try:
                self._diag_timer.delete()
            except Exception:
                pass
            self._diag_timer = None

    def _on_event(self, event, data):
        # runs on the manager's worker thread -> marshal to the UI only if still foreground
        if event == "node":
            self.update_ui_threadsafe_if_foreground(lambda: (self._refresh_nodes(), self._refresh_dms()))
        elif event == "channels":
            self.update_ui_threadsafe_if_foreground(self._refresh_channels)
        elif event == "identity":
            self.update_ui_threadsafe_if_foreground(lambda: (self._refresh_identity(), self._refresh_dms()))
        elif event == "contacts":
            self.update_ui_threadsafe_if_foreground(lambda: (self._refresh_nodes(), self._refresh_dms()))
        elif event == "dm":
            self.update_ui_threadsafe_if_foreground(self._refresh_dms)
        elif event == "message":      # channel message -> unread badge may have changed
            self.update_ui_threadsafe_if_foreground(self._refresh_channels)
        elif event == "unread":       # a chat was read -> clear its badge
            self.update_ui_threadsafe_if_foreground(
                lambda: (self._refresh_channels(), self._refresh_dms()))
        elif event == "service":
            self.update_ui_threadsafe_if_foreground(lambda: self._sync_service_switch(data))

    def _sync_service_switch(self, on):
        if self.service_switch is None:
            return
        if on:
            self.service_switch.add_state(lv.STATE.CHECKED)
        else:
            self.service_switch.remove_state(lv.STATE.CHECKED)


class ChannelChatActivity(Activity):

    def __init__(self):
        super().__init__()
        self.channel = "Public"
        self.manager = None
        self.messages = None
        self.input_textarea = None
        self._sub = None

    def onCreate(self):
        intent = self.getIntent()
        if intent is not None and intent.extras:
            self.channel = intent.extras.get("channel", "Public")

        main_content = lv.obj()
        main_content.set_flex_flow(lv.FLEX_FLOW.COLUMN)
        main_content.set_style_pad_gap(8, 0)

        title = lv.label(main_content)
        title.set_text("# " + self.channel)
        title.set_style_text_font(lv.font_montserrat_16, lv.PART.MAIN)

        # scrollable message area
        msg_area = lv.obj(main_content)
        msg_area.set_width(lv.pct(100))
        msg_area.set_flex_grow(1)
        self.messages = lv.label(msg_area)
        self.messages.set_text("No messages yet.")
        self.messages.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.messages.set_style_text_font(lv.font_montserrat_14, 0)
        self.messages.set_width(lv.pct(100))

        self.input_textarea = lv.textarea(main_content)
        self.input_textarea.set_placeholder_text("Message #%s..." % self.channel)
        self.input_textarea.set_one_line(True)
        self.input_textarea.set_width(lv.pct(100))

        self.keyboard = MposKeyboard(main_content)
        self.keyboard.set_textarea(self.input_textarea)
        self.keyboard.add_flag(lv.obj.FLAG.HIDDEN)

        send_button = _dark(lv.button(main_content))
        send_button.add_event_cb(self._send, lv.EVENT.CLICKED, None)
        lv.label(send_button).set_text("Send")

        self.setContentView(main_content)

    def _render(self):
        mgr = MeshCoreManager.get_instance()
        mgr.clear_unread(self.channel)      # showing the messages == reading them
        msgs = mgr.get_messages(self.channel)
        if not msgs:
            text = "No messages yet."
        else:
            lines = []
            for m in msgs:
                who = ("me" if not m.get("incoming") else m.get("sender", "?"))
                lines.append("%s: %s" % (who, m.get("text", "")))
            text = "\n".join(lines)
        # marshal to the UI thread + skip if the chat is no longer foreground
        self.update_ui_threadsafe_if_foreground(lambda: self.messages.set_text(text))

    def _send(self, event):
        if self.input_textarea is None:
            return
        text = self.input_textarea.get_text()
        if not text:
            return
        self.input_textarea.set_text("")
        MeshCoreManager.get_instance().send_group_text(self.channel, text)

    def onResume(self, screen):
        super().onResume(screen)
        self.manager = MeshCoreManager.get_instance()
        if self.manager.is_service_enabled() and not self.manager.is_running():
            self.manager.start()
        self._render()
        self._sub = lambda ev, data: self._on_event(ev, data)
        self.manager.add_subscriber(self._sub)

    def onPause(self, screen):
        super().onPause(screen)
        if self.manager is not None and self._sub is not None:
            self.manager.remove_subscriber(self._sub)
            self._sub = None

    def _on_event(self, event, data):
        if event == "message" and data and data[0] == self.channel:
            self._render()   # _render marshals to the UI thread + foreground-guards itself


class DMChatActivity(Activity):
    """1:1 encrypted chat with a single contact (identified by its public key)."""

    def __init__(self):
        super().__init__()
        self.pubkey = None
        self.name = None
        self.manager = None
        self.messages = None
        self.input_textarea = None
        self.status = None
        self._sub = None

    def onCreate(self):
        intent = self.getIntent()
        if intent is not None and intent.extras:
            self.pubkey = intent.extras.get("pubkey")
            self.name = intent.extras.get("name")
        if not self.name and self.pubkey:
            m = MeshCoreManager.get_instance()
            entry = m.get_contact(self.pubkey) or m.get_node(self.pubkey)
            self.name = (entry or {}).get("name") or self.pubkey[:2]

        main_content = lv.obj()
        main_content.set_flex_flow(lv.FLEX_FLOW.COLUMN)
        main_content.set_style_pad_gap(8, 0)

        title = lv.label(main_content)
        title.set_text(lv.SYMBOL.CALL + " " + (self.name or "DM"))
        title.set_style_text_font(lv.font_montserrat_16, lv.PART.MAIN)

        msg_area = lv.obj(main_content)
        msg_area.set_width(lv.pct(100))
        msg_area.set_flex_grow(1)
        self.messages = lv.label(msg_area)
        self.messages.set_text("No messages yet.")
        self.messages.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.messages.set_style_text_font(lv.font_montserrat_14, 0)
        self.messages.set_width(lv.pct(100))

        self.input_textarea = lv.textarea(main_content)
        self.input_textarea.set_placeholder_text("Message %s..." % (self.name or ""))
        self.input_textarea.set_one_line(True)
        self.input_textarea.set_width(lv.pct(100))

        self.keyboard = MposKeyboard(main_content)
        self.keyboard.set_textarea(self.input_textarea)
        self.keyboard.add_flag(lv.obj.FLAG.HIDDEN)

        send_button = _dark(lv.button(main_content))
        send_button.add_event_cb(self._send, lv.EVENT.CLICKED, None)
        lv.label(send_button).set_text("Send")

        self.status = lv.label(main_content)
        self.status.set_text("")
        self.status.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.status.set_width(lv.pct(100))

        self.setContentView(main_content)

    def _render(self):
        mgr = MeshCoreManager.get_instance()
        mgr.clear_unread(self.pubkey)       # showing the messages == reading them
        msgs = mgr.get_dm_messages(self.pubkey)
        if not msgs:
            text = "No messages yet."
        else:
            lines = []
            for m in msgs:
                if m.get("incoming"):
                    lines.append("%s: %s" % (m.get("sender", "?"), m.get("text", "")))
                else:
                    # tick once the recipient's ACK comes back (delivery confirmation)
                    mark = (" " + lv.SYMBOL.OK) if m.get("delivered") else ""
                    lines.append("me: %s%s" % (m.get("text", ""), mark))
            text = "\n".join(lines)
        # marshal to the UI thread + skip if the chat is no longer foreground
        self.update_ui_threadsafe_if_foreground(lambda: self.messages.set_text(text))

    def _send(self, event):
        if self.input_textarea is None or not self.pubkey:
            return
        text = self.input_textarea.get_text()
        if not text:
            return
        self.input_textarea.set_text("")
        # send_dm may derive the X25519 secret (~0.6s) if it isn't precomputed yet, so run it
        # off the UI thread to avoid a freeze; the message + delivery tick update via the "dm" event.
        try:
            import _thread
            from mpos import TaskManager
            _thread.stack_size(TaskManager.good_stack_size())
            _thread.start_new_thread(self._send_thread, (text,))
        except Exception:
            self._send_thread(text)

    def _send_thread(self, text):
        ok, err = MeshCoreManager.get_instance().send_dm(self.pubkey, text)
        msg = ("Send failed: %s" % err) if not ok else ""
        self.update_ui_threadsafe_if_foreground(lambda: self.status.set_text(msg))

    def onResume(self, screen):
        super().onResume(screen)
        self.manager = MeshCoreManager.get_instance()
        if self.manager.is_service_enabled() and not self.manager.is_running():
            self.manager.start()
        self._render()
        self._sub = lambda ev, data: self._on_event(ev, data)
        self.manager.add_subscriber(self._sub)

    def onPause(self, screen):
        super().onPause(screen)
        if self.manager is not None and self._sub is not None:
            self.manager.remove_subscriber(self._sub)
            self._sub = None

    def _on_event(self, event, data):
        if event == "dm" and data and data[0] == self.pubkey:
            self._render()   # _render marshals to the UI thread + foreground-guards itself


class ShareQRActivity(Activity):
    """Render a meshcore:// URI as a QR for the MeshCore mobile app to scan.

    Intent extras: title, uri, note (all strings). Used for both contact cards
    (meshcore://contact/add?...) and channel links (meshcore://channel/add?...)."""

    def onCreate(self):
        intent = self.getIntent()
        extras = intent.extras if intent is not None else {}
        uri = (extras or {}).get("uri")
        if not uri:
            self._error("Nothing to share.")
            return
        title = (extras or {}).get("title", "Scan me")
        note = (extras or {}).get("note", "Scan in the MeshCore mobile app.")

        screen = lv.obj()
        screen.set_flex_flow(lv.FLEX_FLOW.COLUMN)
        screen.set_flex_align(lv.FLEX_ALIGN.CENTER, lv.FLEX_ALIGN.CENTER, lv.FLEX_ALIGN.CENTER)
        screen.set_style_pad_all(DisplayMetrics.pct_of_width(3), lv.PART.MAIN)
        screen.set_style_pad_gap(8, 0)
        screen.set_scrollbar_mode(lv.SCROLLBAR_MODE.ACTIVE)
        screen.add_event_cb(lambda e: self.finish(), lv.EVENT.CLICKED, None)

        title_lbl = lv.label(screen)
        title_lbl.set_text(title)
        title_lbl.set_style_text_font(lv.font_montserrat_16, lv.PART.MAIN)

        qr_size = round(DisplayMetrics.min_dimension() * 0.6)
        qr = lv.qrcode(screen)
        qr.set_size(qr_size)
        # white quiet-zone border so the code stays scannable on any background
        qr.set_style_border_color(lv.color_white(), 0)
        qr.set_style_border_width(6, 0)
        qr.update(uri, len(uri))

        note_lbl = lv.label(screen)
        note_lbl.set_text(note)
        note_lbl.set_style_text_font(lv.font_montserrat_12, lv.PART.MAIN)
        note_lbl.set_long_mode(lv.label.LONG_MODE.WRAP)
        note_lbl.set_width(lv.pct(100))
        note_lbl.set_style_text_align(lv.TEXT_ALIGN.CENTER, lv.PART.MAIN)

        self.setContentView(screen)

    def _error(self, text):
        screen = lv.obj()
        screen.add_event_cb(lambda e: self.finish(), lv.EVENT.CLICKED, None)
        label = lv.label(screen)
        label.set_text(text)
        label.center()
        self.setContentView(screen)
