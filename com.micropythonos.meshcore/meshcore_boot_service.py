# Boot-time service for the MeshCore app.
#
# Started at boot by AppManager.start_boot_services() (declared in MANIFEST.JSON with
# action "boot_completed").  It starts the MeshCore radio manager only if the app-local
# "background radio service" toggle is enabled -- this is what makes the node listen
# passively in the background without the UI being opened.  The toggle is set live from the
# Me tab (and persists), so no reboot is needed to enable/disable; this just honours the
# last state at boot. If the toggle is off, the service exits and leaves the radio alone.

from mpos import Service

# Import the manager at module load time: the app dir is on sys.path during this import,
# but not later when onStart() runs, so importing here caches it in sys.modules.
from meshcore_manager import MeshCoreManager


class MeshCoreBootService(Service):

    def onStart(self, intent):
        m = MeshCoreManager.get_instance()
        if m.is_service_enabled():
            print("MeshCoreBootService: service enabled, starting background MeshCore receiver")
            m.start()
        else:
            print("MeshCoreBootService: service disabled, staying off")
