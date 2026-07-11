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
        self._sub = None

    def onCreate(self):
        screen = lv.obj()
        tabview = lv.tabview(screen)
        tabview.set_tab_bar_size(36)

        self._build_channels_tab(tabview.add_tab("Channels"))
        self._build_nodes_tab(tabview.add_tab("Companions"))
        self._build_dms_tab(tabview.add_tab("Contacts"))
        self._build_me_tab(tabview.add_tab("Me"))

        self.setContentView(screen)

    # --- tabs --------------------------------------------------------------- #
    def _build_channels_tab(self, tab):
        self.channels_list = lv.list(tab)
        self.channels_list.set_size(lv.pct(100), lv.pct(100))

    def _refresh_channels(self):
        if self.channels_list is None:
            return
        self.channels_list.clean()
        add_btn = self.channels_list.add_button(None, "+ New channel")
        add_btn.add_event_cb(lambda e: self._prompt_add_channel(), lv.EVENT.CLICKED, None)
        self.channels_list.add_text("Tap to open, long-press to remove")
        for name in MeshCoreManager.get_instance().get_channel_names():
            btn = self.channels_list.add_button(None, "# " + name)
            btn.add_event_cb(lambda e, n=name: self._open_channel(n), lv.EVENT.CLICKED, None)
            if name != "Public":
                # long-press to remove a custom channel
                btn.add_event_cb(lambda e, n=name: self._remove_channel(n),
                                 lv.EVENT.LONG_PRESSED, None)

    def _open_channel(self, name):
        self.startActivity(Intent(activity_class=ChannelChatActivity, extras={"channel": name}))

    def _prompt_add_channel(self):
        setting = {"key": "channel", "title": "Add channel", "ui": "textarea",
                   "placeholder": "name = public #name   (name|base64key = private)"}
        self.startActivityForResult(
            Intent(activity_class=InputActivity, extras={"setting": setting}),
            self._on_add_channel)

    def _on_add_channel(self, result):
        print("MeshCore: add-channel result:", result)
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

    def _remove_channel(self, name):
        MeshCoreManager.get_instance().remove_channel(name)
        lv.async_call(lambda _: self._refresh_channels(), None)

    def _build_nodes_tab(self, tab):
        self.nodes_list = lv.list(tab)
        self.nodes_list.set_size(lv.pct(100), lv.pct(100))

    def _refresh_nodes(self):
        # "Companions" tab: companions learned via advert this session (RAM only).
        if self.nodes_list is None:
            return
        self.nodes_list.clean()
        m = MeshCoreManager.get_instance()
        companions = m.get_learned_companions()
        if not companions:
            self.nodes_list.add_button(None, "No companions heard yet...")
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

    def _build_dms_tab(self, tab):
        self.dms_list = lv.list(tab)
        self.dms_list.set_size(lv.pct(100), lv.pct(100))

    def _refresh_dms(self):
        # "Contacts" tab: the saved contact list (only these can be chatted with).
        if self.dms_list is None:
            return
        self.dms_list.clean()
        m = MeshCoreManager.get_instance()
        if not m.has_identity():
            self.dms_list.add_button(None, "Generate an identity (Me tab) to use DMs")
            return
        contacts = m.get_contacts()
        if not contacts:
            self.dms_list.add_button(None, "No contacts yet -- add a companion from "
                                           "the Companions tab")
            return
        self.dms_list.add_text("Tap to chat, long-press to remove")
        for c in contacts:
            name = c.get("name") or ("id " + c.get("id", "??"))
            pub = c.get("pubkey")
            btn = self.dms_list.add_button(None, "%s  %s" % (name, c.get("id", "")))
            if pub:
                btn.add_event_cb(lambda e, p=pub, nm=name: self._open_dm(p, nm),
                                 lv.EVENT.CLICKED, None)
                btn.add_event_cb(lambda e, p=pub: self._remove_contact(p),
                                 lv.EVENT.LONG_PRESSED, None)

    def _remove_contact(self, pubkey_hex):
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
                          "Off = radio idle. Turn off before using the LoRa Chat app.")
        svc_note.set_long_mode(lv.label.LONG_MODE.WRAP)
        svc_note.set_width(lv.pct(100))
        svc_note.set_style_text_font(lv.font_montserrat_12, lv.PART.MAIN)

        self.name_label = lv.label(tab)
        self.name_label.set_text("Name: " + MeshCoreManager.get_instance().nickname())
        self.name_label.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.name_label.set_width(lv.pct(100))

        name_btn = lv.button(tab)
        name_btn.add_event_cb(lambda e: self._prompt_name(), lv.EVENT.CLICKED, None)
        lv.label(name_btn).set_text("Edit name")

        # --- identity ---
        self.identity_label = lv.label(tab)
        self.identity_label.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.identity_label.set_width(lv.pct(100))

        self.gen_id_btn = lv.button(tab)
        self.gen_id_btn.add_event_cb(lambda e: self._generate_identity(), lv.EVENT.CLICKED, None)
        lv.label(self.gen_id_btn).set_text("Generate identity (slow)")

        self.backup_id_btn = lv.button(tab)
        self.backup_id_btn.add_event_cb(lambda e: self._backup_identity(), lv.EVENT.CLICKED, None)
        lv.label(self.backup_id_btn).set_text("Backup keys to SD")

        self.advert_btn = lv.button(tab)
        self.advert_btn.add_event_cb(lambda e: self._advertise_now(), lv.EVENT.CLICKED, None)
        lv.label(self.advert_btn).set_text("Advertise now")

        self.share_qr_btn = lv.button(tab)
        self.share_qr_btn.add_event_cb(lambda e: self._share_contact(), lv.EVENT.CLICKED, None)
        lv.label(self.share_qr_btn).set_text("Share my contact (QR)")

        restart_btn = lv.button(tab)
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
        # keygen is slow (pure-Python) -> run off the UI thread
        lv.async_call(lambda _: self.identity_label.set_text("Generating identity...\n(may take a while)"), None)
        try:
            import _thread
            from mpos import TaskManager
            _thread.stack_size(TaskManager.good_stack_size())
            _thread.start_new_thread(self._generate_identity_thread, ())
        except Exception as e:
            print("MeshCoreHome: could not start keygen thread:", repr(e))
            self._generate_identity_thread()

    def _generate_identity_thread(self):
        MeshCoreManager.get_instance().generate_identity()
        lv.async_call(lambda _: self._refresh_identity(), None)

    def _backup_identity(self):
        ok, info = MeshCoreManager.get_instance().backup_identity_to_sd()
        msg = ("Backed up to %s" % info) if ok else ("Backup failed: %s" % info)
        print("MeshCoreHome: backup ->", msg)
        lv.async_call(lambda _: self.identity_label.set_text(self.identity_label.get_text() + "\n" + msg), None)

    def _advertise_now(self):
        # signing is slow -> run off the UI thread
        lv.async_call(lambda _: self.identity_label.set_text(self.identity_label.get_text() + "\nAdvertising..."), None)
        try:
            import _thread
            from mpos import TaskManager
            _thread.stack_size(TaskManager.good_stack_size())
            _thread.start_new_thread(self._advertise_thread, ())
        except Exception:
            self._advertise_thread()

    def _advertise_thread(self):
        ok, err = MeshCoreManager.get_instance().advertise()
        line = "Advertised." if ok else ("Advert failed: %s" % err)
        lv.async_call(lambda _: (self._refresh_identity(),
                                 self.identity_label.set_text(self.identity_label.get_text() + "\n" + line)), None)

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
        on = self.service_switch.has_state(lv.STATE.CHECKED)
        print("MeshCoreHome: radio service toggled", "on" if on else "off")
        MeshCoreManager.get_instance().set_service_enabled(on)

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

    def onPause(self, screen):
        super().onPause(screen)
        if self.manager is not None and self._sub is not None:
            self.manager.remove_subscriber(self._sub)
            self._sub = None

    def _on_event(self, event, data):
        if event == "node":
            lv.async_call(lambda _: (self._refresh_nodes(), self._refresh_dms()), None)
        elif event == "channels":
            lv.async_call(lambda _: self._refresh_channels(), None)
        elif event == "identity":
            lv.async_call(lambda _: (self._refresh_identity(), self._refresh_dms()), None)
        elif event == "contacts":
            lv.async_call(lambda _: (self._refresh_nodes(), self._refresh_dms()), None)
        elif event == "dm":
            lv.async_call(lambda _: self._refresh_dms(), None)
        elif event == "service":
            lv.async_call(lambda _: self._sync_service_switch(data), None)

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

        send_button = lv.button(main_content)
        send_button.add_event_cb(self._send, lv.EVENT.CLICKED, None)
        lv.label(send_button).set_text("Send")

        self.setContentView(main_content)

    def _render(self):
        msgs = MeshCoreManager.get_instance().get_messages(self.channel)
        if not msgs:
            text = "No messages yet."
        else:
            lines = []
            for m in msgs:
                who = ("me" if not m.get("incoming") else m.get("sender", "?"))
                lines.append("%s: %s" % (who, m.get("text", "")))
            text = "\n".join(lines)
        lv.async_call(lambda _: self.messages.set_text(text), None)

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
            lv.async_call(lambda _: self._render(), None)


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

        send_button = lv.button(main_content)
        send_button.add_event_cb(self._send, lv.EVENT.CLICKED, None)
        lv.label(send_button).set_text("Send")

        self.status = lv.label(main_content)
        self.status.set_text("")
        self.status.set_long_mode(lv.label.LONG_MODE.WRAP)
        self.status.set_width(lv.pct(100))

        self.setContentView(main_content)

    def _render(self):
        msgs = MeshCoreManager.get_instance().get_dm_messages(self.pubkey)
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
        lv.async_call(lambda _: self.messages.set_text(text), None)

    def _send(self, event):
        if self.input_textarea is None or not self.pubkey:
            return
        text = self.input_textarea.get_text()
        if not text:
            return
        self.input_textarea.set_text("")
        ok, err = MeshCoreManager.get_instance().send_dm(self.pubkey, text)
        if not ok:
            lv.async_call(lambda _: self.status.set_text("Send failed: %s" % err), None)
        else:
            lv.async_call(lambda _: self.status.set_text(""), None)

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
            lv.async_call(lambda _: self._render(), None)


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
