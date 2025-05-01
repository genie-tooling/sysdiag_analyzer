import pytest
import json
import datetime # Added for log parsing tests
from unittest.mock import patch, MagicMock, call, ANY
from typing import List, Optional # Added List, Optional

# Modules to test
from sysdiag_analyzer.modules import health
from sysdiag_analyzer.datatypes import HealthAnalysisResult, UnitHealthInfo
from sysdiag_analyzer import utils # To mock run_subprocess

# --- Mock Data (remains the same) ---
class MockDBusException(Exception):
    _dbus_error_name = "org.freedesktop.DBus.Error.Mock"
    def __init__(self, message="Mock DBus Error", error_name=None):
        super().__init__(message)
        self._dbus_error_name = error_name if error_name else self._dbus_error_name
if not health.HAS_DBUS:
    MockDBusString, MockDBusObjectPath, MockDBusInt32, MockDBusUInt32, MockDBusInt64, MockDBusUInt64, MockDBusByte, MockDBusDouble, MockDBusBoolean, MockDBusArray, MockDBusDictionary = str, str, int, int, int, int, int, float, bool, list, dict
else:
    MockDBusString, MockDBusObjectPath, MockDBusInt32, MockDBusUInt32, MockDBusInt64, MockDBusUInt64, MockDBusByte, MockDBusDouble, MockDBusBoolean, MockDBusArray, MockDBusDictionary = health.dbus.String, health.dbus.ObjectPath, health.dbus.Int32, health.dbus.UInt32, health.dbus.Int64, health.dbus.UInt64, health.dbus.Byte, health.dbus.Double, health.dbus.Boolean, health.dbus.Array, health.dbus.Dictionary
class MockSystemBus:
    def __init__(self):
        self._objects = {}
        self.mock_manager_obj = MagicMock(spec=['Interface'])
        self.mock_manager_iface = MagicMock(spec=['ListUnits', 'GetUnit'])
        self.mock_manager_iface.ListUnits.return_value = MOCK_DBUS_LIST_UNITS_RAW
        self.mock_manager_iface.bus = self
        self.mock_manager_obj.Interface.side_effect = lambda iface_name: self.mock_manager_iface if iface_name == 'org.freedesktop.systemd1.Manager' else MagicMock()
    def get_object(self, bus_name, object_path):
        if object_path == '/org/freedesktop/systemd1':
            return self.mock_manager_obj
        mock_unit_obj = MagicMock(spec=['Interface'], name=f"MockUnitObj_{object_path.split('/')[-1]}")
        mock_unit_obj.object_path = object_path
        self._objects[object_path] = mock_unit_obj
        return mock_unit_obj
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
MOCK_DBUS_LIST_UNITS_RAW = [(MockDBusString('good.service'), MockDBusString('Good Service Desc'), MockDBusString('loaded'), MockDBusString('active'), MockDBusString('running'), MockDBusString(''), MockDBusObjectPath('/org/freedesktop/systemd1/unit/good_2eservice'), MockDBusUInt32(0), MockDBusString(''), MockDBusString('')), (MockDBusString('failed.service'), MockDBusString('Failed Service Desc'), MockDBusString('loaded'), MockDBusString('failed'), MockDBusString('failed'), MockDBusString(''), MockDBusObjectPath('/org/freedesktop/systemd1/unit/failed_2eservice'), MockDBusUInt32(0), MockDBusString(''), MockDBusString('')), (MockDBusString('flapping.service'), MockDBusString('Flapping Service Desc'), MockDBusString('loaded'), MockDBusString('active'), MockDBusString('reloading'), MockDBusString(''), MockDBusObjectPath('/org/freedesktop/systemd1/unit/flapping_2eservice'), MockDBusUInt32(0), MockDBusString(''), MockDBusString('')), (MockDBusString('refused.socket'), MockDBusString('Refused Socket Desc'), MockDBusString('loaded'), MockDBusString('active'), MockDBusString('listening'), MockDBusString(''), MockDBusObjectPath('/org/freedesktop/systemd1/unit/refused_2esocket'), MockDBusUInt32(0), MockDBusString(''), MockDBusString('')), (MockDBusString('good.socket'), MockDBusString('Good Socket Desc'), MockDBusString('loaded'), MockDBusString('active'), MockDBusString('listening'), MockDBusString(''), MockDBusObjectPath('/org/freedesktop/systemd1/unit/good_2esocket'), MockDBusUInt32(0), MockDBusString(''), MockDBusString('')), (MockDBusString('badtimer.timer'), MockDBusString('Bad Timer Desc'), MockDBusString('loaded'), MockDBusString('active'), MockDBusString('waiting'), MockDBusString(''), MockDBusObjectPath('/org/freedesktop/systemd1/unit/badtimer_2etimer'), MockDBusUInt32(0), MockDBusString(''), MockDBusString('')), (MockDBusString('good.timer'), MockDBusString('Good Timer Desc'), MockDBusString('loaded'), MockDBusString('active'), MockDBusString('waiting'), MockDBusString(''), MockDBusObjectPath('/org/freedesktop/systemd1/unit/good_2etimer'), MockDBusUInt32(0), MockDBusString(''), MockDBusString('')), (MockDBusString('notfound.service'), MockDBusString('Not Found Desc'), MockDBusString('not-found'), MockDBusString('inactive'), MockDBusString('dead'), MockDBusString(''), MockDBusObjectPath('/org/freedesktop/systemd1/unit/notfound_2eservice'), MockDBusUInt32(0), MockDBusString(''), MockDBusString(''))]
MOCK_DBUS_PROPS_RAW_GOOD_SERVICE = {MockDBusString('org.freedesktop.systemd1.Unit'): {MockDBusString('Id'): MockDBusString('good.service'), MockDBusString('LoadState'): MockDBusString('loaded'), MockDBusString('ActiveState'): MockDBusString('active'), MockDBusString('SubState'): MockDBusString('running')}, MockDBusString('org.freedesktop.systemd1.Service'): {MockDBusString('NRestarts'): MockDBusUInt32(0), MockDBusString('Result'): MockDBusString('success')}}
MOCK_DBUS_PROPS_RAW_FAILED_SERVICE = {MockDBusString('org.freedesktop.systemd1.Unit'): {MockDBusString('Id'): MockDBusString('failed.service'), MockDBusString('LoadState'): MockDBusString('loaded'), MockDBusString('ActiveState'): MockDBusString('failed'), MockDBusString('SubState'): MockDBusString('failed')}, MockDBusString('org.freedesktop.systemd1.Service'): {MockDBusString('NRestarts'): MockDBusUInt32(1), MockDBusString('Result'): MockDBusString('exit-code'), MockDBusString('ExecMainStatus'): MockDBusInt32(1)}}
MOCK_DBUS_PROPS_RAW_FLAPPING_SERVICE = {MockDBusString('org.freedesktop.systemd1.Unit'): {MockDBusString('Id'): MockDBusString('flapping.service'), MockDBusString('LoadState'): MockDBusString('loaded'), MockDBusString('ActiveState'): MockDBusString('active'), MockDBusString('SubState'): MockDBusString('reloading')}, MockDBusString('org.freedesktop.systemd1.Service'): {MockDBusString('NRestarts'): MockDBusUInt32(5), MockDBusString('Result'): MockDBusString('success')}}
MOCK_DBUS_PROPS_RAW_REFUSED_SOCKET = {MockDBusString('org.freedesktop.systemd1.Unit'): {MockDBusString('Id'): MockDBusString('refused.socket'), MockDBusString('LoadState'): MockDBusString('loaded'), MockDBusString('ActiveState'): MockDBusString('active'), MockDBusString('SubState'): MockDBusString('listening')}, MockDBusString('org.freedesktop.systemd1.Socket'): {MockDBusString('Refused'): MockDBusBoolean(True), MockDBusString('NAccepted'): MockDBusUInt32(0), MockDBusString('NConnections'): MockDBusUInt32(0)}}
MOCK_DBUS_PROPS_RAW_GOOD_SOCKET = {MockDBusString('org.freedesktop.systemd1.Unit'): {MockDBusString('Id'): MockDBusString('good.socket'), MockDBusString('LoadState'): MockDBusString('loaded'), MockDBusString('ActiveState'): MockDBusString('active'), MockDBusString('SubState'): MockDBusString('listening')}, MockDBusString('org.freedesktop.systemd1.Socket'): {MockDBusString('Refused'): MockDBusBoolean(False), MockDBusString('NAccepted'): MockDBusUInt32(10), MockDBusString('NConnections'): MockDBusUInt32(1)}}
MOCK_DBUS_PROPS_RAW_BAD_TIMER = {MockDBusString('org.freedesktop.systemd1.Unit'): {MockDBusString('Id'): MockDBusString('badtimer.timer'), MockDBusString('LoadState'): MockDBusString('loaded'), MockDBusString('ActiveState'): MockDBusString('active'), MockDBusString('SubState'): MockDBusString('waiting')}, MockDBusString('org.freedesktop.systemd1.Timer'): {MockDBusString('Result'): MockDBusString('resources'), MockDBusString('LastTriggerUSec'): MockDBusUInt64(1678886461123456)}}
MOCK_DBUS_PROPS_RAW_GOOD_TIMER = {MockDBusString('org.freedesktop.systemd1.Unit'): {MockDBusString('Id'): MockDBusString('good.timer'), MockDBusString('LoadState'): MockDBusString('loaded'), MockDBusString('ActiveState'): MockDBusString('active'), MockDBusString('SubState'): MockDBusString('waiting')}, MockDBusString('org.freedesktop.systemd1.Timer'): {MockDBusString('Result'): MockDBusString('success'), MockDBusString('LastTriggerUSec'): MockDBusUInt64(1678886400000000)}}
PATH_TO_RAW_PROPS = {'/org/freedesktop/systemd1/unit/good_2eservice': MOCK_DBUS_PROPS_RAW_GOOD_SERVICE, '/org/freedesktop/systemd1/unit/failed_2eservice': MOCK_DBUS_PROPS_RAW_FAILED_SERVICE, '/org/freedesktop/systemd1/unit/flapping_2eservice': MOCK_DBUS_PROPS_RAW_FLAPPING_SERVICE, '/org/freedesktop/systemd1/unit/refused_2esocket': MOCK_DBUS_PROPS_RAW_REFUSED_SOCKET, '/org/freedesktop/systemd1/unit/good_2esocket': MOCK_DBUS_PROPS_RAW_GOOD_SOCKET, '/org/freedesktop/systemd1/unit/badtimer_2etimer': MOCK_DBUS_PROPS_RAW_BAD_TIMER, '/org/freedesktop/systemd1/unit/good_2etimer': MOCK_DBUS_PROPS_RAW_GOOD_TIMER}
PATH_TO_INTROSPECTION = {'/org/freedesktop/systemd1/unit/good_2eservice': '<node><interface name="org.freedesktop.systemd1.Unit"></interface><interface name="org.freedesktop.systemd1.Service"></interface></node>', '/org/freedesktop/systemd1/unit/failed_2eservice': '<node><interface name="org.freedesktop.systemd1.Unit"></interface><interface name="org.freedesktop.systemd1.Service"></interface></node>', '/org/freedesktop/systemd1/unit/flapping_2eservice': '<node><interface name="org.freedesktop.systemd1.Unit"></interface><interface name="org.freedesktop.systemd1.Service"></interface></node>', '/org/freedesktop/systemd1/unit/refused_2esocket': '<node><interface name="org.freedesktop.systemd1.Unit"></interface><interface name="org.freedesktop.systemd1.Socket"></interface></node>', '/org/freedesktop/systemd1/unit/good_2esocket': '<node><interface name="org.freedesktop.systemd1.Unit"></interface><interface name="org.freedesktop.systemd1.Socket"></interface></node>', '/org/freedesktop/systemd1/unit/badtimer_2etimer': '<node><interface name="org.freedesktop.systemd1.Unit"></interface><interface name="org.freedesktop.systemd1.Timer"></interface></node>', '/org/freedesktop/systemd1/unit/good_2etimer': '<node><interface name="org.freedesktop.systemd1.Unit"></interface><interface name="org.freedesktop.systemd1.Timer"></interface></node>'}
MOCK_SYSTEMCTL_LIST_UNITS_JSON = json.dumps([{"unit": "good.service", "load": "loaded", "active": "active", "sub": "running", "description": "Good Service Desc"}, {"unit": "failed.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "Failed Service Desc"}, {"unit": "flapping.service", "load": "loaded", "active": "active", "sub": "reloading", "description": "Flapping Service Desc"}, {"unit": "refused.socket", "load": "loaded", "active": "active", "sub": "listening", "description": "Refused Socket Desc"}, {"unit": "good.socket", "load": "loaded", "active": "active", "sub": "listening", "description": "Good Socket Desc"}, {"unit": "badtimer.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": "Bad Timer Desc"}, {"unit": "good.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": "Good Timer Desc"}, {"unit": "notfound.service", "load": "not-found", "active": "inactive", "sub": "dead", "description": "Not Found Desc"}])
MOCK_SYSTEMCTL_SHOW_FAILED = "Id=failed.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\nNRestarts=1"; MOCK_SYSTEMCTL_SHOW_FLAPPING = "Id=flapping.service\nLoadState=loaded\nActiveState=active\nSubState=reloading\nResult=success\nNRestarts=5"; MOCK_SYSTEMCTL_SHOW_REFUSED_SOCKET = "Id=refused.socket\nLoadState=loaded\nActiveState=active\nSubState=listening\nRefused=yes"; MOCK_SYSTEMCTL_SHOW_BAD_TIMER = "Id=badtimer.timer\nLoadState=loaded\nActiveState=active\nSubState=waiting\nResult=resources\nLastTriggerUSec=1678886461123456"; MOCK_SYSTEMCTL_SHOW_GOOD = "Id=good.service\nLoadState=loaded\nActiveState=active\nSubState=running\nNRestarts=0\nResult=success"; MOCK_SYSTEMCTL_SHOW_NOTFOUND = "Id=notfound.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=/dev/null"
MOCK_JOURNALCTL_FAILED_LOGS = "2023-03-15T13:21:01+0000 hostname systemd[1]: Starting Failed Service...\n2023-03-15T13:21:02+0000 hostname failed.service[1234]: Error message from service\n2023-03-15T13:21:02+0000 hostname systemd[1]: failed.service: Main process exited, code=exited, status=1/FAILURE\n2023-03-15T13:21:02+0000 hostname systemd[1]: failed.service: Failed with result 'exit-code'."
MOCK_JOURNALCTL_FLAPPING_LOGS = "2023-03-15T13:20:01+0000 hostname systemd[1]: Starting Flapping Service...\n2023-03-15T13:20:01+0000 hostname systemd[1]: Started Flapping Service.\n2023-03-15T13:20:05+0000 hostname systemd[1]: Stopping Flapping Service...\n2023-03-15T13:20:05+0000 hostname systemd[1]: Stopped Flapping Service.\n2023-03-15T13:20:10+0000 hostname systemd[1]: Starting Flapping Service...\n2023-03-15T13:20:10+0000 hostname systemd[1]: Started Flapping Service."
MOCK_NATIVE_LOG_ENTRIES = [{"_SYSTEMD_UNIT": "some.service", "MESSAGE": "Native Log 3", "__REALTIME_TIMESTAMP": 1700000003000000, "date": datetime.datetime.fromtimestamp(1700000003, tz=datetime.timezone.utc)}, {"_SYSTEMD_UNIT": "some.service", "MESSAGE": "Native Log 2", "__REALTIME_TIMESTAMP": 1700000002000000, "date": datetime.datetime.fromtimestamp(1700000002, tz=datetime.timezone.utc)}, {"_SYSTEMD_UNIT": "some.service", "MESSAGE": "Native Log 1", "__REALTIME_TIMESTAMP": 1700000001000000, "date": datetime.datetime.fromtimestamp(1700000001, tz=datetime.timezone.utc)}]
EXPECTED_NATIVE_LOGS_FORMATTED = ["2023-11-14T22:13:21.000+00:00 - Native Log 1", "2023-11-14T22:13:22.000+00:00 - Native Log 2", "2023-11-14T22:13:23.000+00:00 - Native Log 3"]

# --- Fixtures ---
@pytest.fixture
def mock_dbus_systembus():
    """Mocks dbus.SystemBus and related components."""
    if not health.HAS_DBUS:
        yield None
        return
    mock_bus_instance = MockSystemBus()
    with patch('sysdiag_analyzer.modules.health.dbus') as mock_dbus_module:
        mock_dbus_module.SystemBus = MagicMock(return_value=mock_bus_instance)
        mock_dbus_module.Interface = MagicMock()
        mock_dbus_module.exceptions = MagicMock()
        mock_dbus_module.exceptions.DBusException = MockDBusException
        mock_dbus_module.String = MockDBusString
        mock_dbus_module.ObjectPath = MockDBusObjectPath
        mock_dbus_module.Int32 = MockDBusInt32
        mock_dbus_module.UInt32 = MockDBusUInt32
        mock_dbus_module.Int64 = MockDBusInt64
        mock_dbus_module.UInt64 = MockDBusUInt64
        mock_dbus_module.Byte = MockDBusByte
        mock_dbus_module.Double = MockDBusDouble
        mock_dbus_module.Boolean = MockDBusBoolean
        mock_dbus_module.Array = MockDBusArray
        mock_dbus_module.Dictionary = MockDBusDictionary
        yield mock_bus_instance

@pytest.fixture
def mock_dbus_interface(mock_dbus_systembus):
    """Mocks the dbus.Interface class, coordinating with MockSystemBus."""
    if not health.HAS_DBUS:
        yield None
        return
    bus_instance = mock_dbus_systembus
    manager_obj = bus_instance.mock_manager_obj
    manager_iface = bus_instance.mock_manager_iface
    def interface_factory(dbus_object_mock, interface_name):
        if dbus_object_mock == manager_obj and interface_name == 'org.freedesktop.systemd1.Manager':
            return manager_iface
        object_path = getattr(dbus_object_mock, 'object_path', 'N/A')
        if interface_name == 'org.freedesktop.DBus.Properties':
            props_iface = MagicMock(spec=['GetAll'])
            raw_props_map_for_path = PATH_TO_RAW_PROPS.get(object_path, {})
            def get_all_side_effect(iface_arg):
                props_for_interface = raw_props_map_for_path.get(iface_arg, {})
                if not props_for_interface:
                     if object_path == '/org/freedesktop/systemd1/unit/notfound_2eservice':
                          raise MockDBusException(f"Mock properties not found for interface {iface_arg} on path {object_path}", error_name="org.freedesktop.DBus.Error.UnknownInterface")
                     else:
                          if object_path not in PATH_TO_RAW_PROPS:
                               raise MockDBusException(f"Mock object path {object_path} unknown in test setup", error_name="org.freedesktop.DBus.Error.ServiceUnknown")
                          else:
                               return {}
                return props_for_interface
            props_iface.GetAll.side_effect = get_all_side_effect
            return props_iface
        elif interface_name == 'org.freedesktop.DBus.Introspectable':
            intro_iface = MagicMock(spec=['Introspect'])
            intro_xml = PATH_TO_INTROSPECTION.get(object_path, '<node></node>')
            intro_iface.Introspect.return_value = intro_xml
            return intro_iface
        else:
            return MagicMock(name=f"GenericMock_{interface_name.split('.')[-1]}")
    mock_dbus_module = health.dbus
    mock_dbus_module.Interface = MagicMock(side_effect=interface_factory)
    yield mock_dbus_module.Interface

@pytest.fixture
def mock_journal_reader():
    """Mocks the native journal reader."""
    if health.HAS_NATIVE_JOURNAL:
        with patch('sysdiag_analyzer.modules.health.JournalReader') as mock_reader_cls:
            mock_instance = MagicMock()
            mock_data = [d.copy() for d in MOCK_NATIVE_LOG_ENTRIES] # Reverse chronological
            if health.HAS_CYSYSTEMD:
                mock_records = []
                for entry in reversed(mock_data): # Iterate chronological (Log 1, 2, 3)
                    record = MagicMock()
                    record.data = entry
                    record.date = entry['date']
                    record.get_realtime_usec.return_value = entry['__REALTIME_TIMESTAMP']
                    mock_records.append(record)
                def previous_effect_cysystemd(*args, **kwargs):
                    if mock_records:
                        mock_instance.current_record = mock_records.pop() # Get newest remaining
                        return True
                    mock_instance.current_record = None
                    return False
                mock_instance.previous.side_effect = previous_effect_cysystemd
                mock_instance.current_record = None # Initialize current_record
            elif health.HAS_PYTHON_SYSTEMD:
                 mock_instance.previous.side_effect = [True] * len(mock_data) + [False]
                 mock_instance.get_data.side_effect = list(reversed(mock_data)) # Log 1, 2, 3
            mock_instance.open.return_value = None
            mock_instance.add_filter.return_value = None
            mock_instance.add_match.return_value = None
            mock_instance.seek_tail.return_value = None
            mock_instance.close.return_value = None
            mock_reader_cls.return_value = mock_instance
            yield mock_reader_cls
    else:
        yield None

# --- Helper Function for Mocking run_subprocess Side Effect ---
def configure_run_subprocess_mock(mock_obj):
     def side_effect(command):
         cmd_str = " ".join(command)
         if "systemctl list-units" in cmd_str and "--output=json" in cmd_str:
             return (True, MOCK_SYSTEMCTL_LIST_UNITS_JSON, "")
         elif "systemctl show failed.service" in cmd_str:
             return (True, MOCK_SYSTEMCTL_SHOW_FAILED, "")
         elif "systemctl show flapping.service" in cmd_str:
             return (True, MOCK_SYSTEMCTL_SHOW_FLAPPING, "")
         elif "systemctl show refused.socket" in cmd_str:
             return (True, MOCK_SYSTEMCTL_SHOW_REFUSED_SOCKET, "")
         elif "systemctl show badtimer.timer" in cmd_str:
             return (True, MOCK_SYSTEMCTL_SHOW_BAD_TIMER, "")
         elif "systemctl show good.service" in cmd_str:
             return (True, MOCK_SYSTEMCTL_SHOW_GOOD, "")
         elif "systemctl show notfound.service" in cmd_str:
             return (True, MOCK_SYSTEMCTL_SHOW_NOTFOUND, "")
         elif "journalctl -u failed.service" in cmd_str:
             return (True, MOCK_JOURNALCTL_FAILED_LOGS, "")
         elif "journalctl -u flapping.service" in cmd_str:
             return (True, MOCK_JOURNALCTL_FLAPPING_LOGS, "")
         elif "journalctl" in cmd_str: # Generic fallback for other journal calls
             return (True, "2023-01-01T10:00:00+0000 Log line 1\n2023-01-01T10:00:01+0000 Log line 2", "")
         elif "systemctl show" in cmd_str: # Generic fallback for other show calls
              unit_name = command[2]
              return (False, "", f"Unit {unit_name} not loaded.")
         else: # Default for unmocked commands
             return (False, "", f"Unmocked command: {cmd_str}")
     mock_obj.side_effect = side_effect


@pytest.fixture
def mock_units_list() -> List[UnitHealthInfo]:
    """Provides a list of mock UnitHealthInfo objects based on MOCK_DBUS_LIST_UNITS_RAW"""
    units = []
    for u in MOCK_DBUS_LIST_UNITS_RAW:
        if isinstance(u, (list, tuple)) and len(u) >= 7:
            unit_info = UnitHealthInfo(
                name=str(u[0]), description=str(u[1]), load_state=str(u[2]),
                active_state=str(u[3]), sub_state=str(u[4]), path=str(u[6])
            )
            units.append(unit_info)
    return units

# --- Test Functions ---

# --- Test Property Fetching (No change needed) ---
@pytest.mark.skipif(not health.HAS_DBUS, reason="DBus bindings not installed")
def test_get_unit_properties_dbus_success(mock_dbus_systembus, mock_dbus_interface):
    bus = mock_dbus_systembus
    props = health._get_unit_properties_dbus(bus, '/org/freedesktop/systemd1/unit/failed_2eservice')
    assert props is not None
    assert props.get('Id') == 'failed.service'
    assert props.get('ActiveState') == 'failed'
    assert props.get('Result') == 'exit-code'
    assert props.get('NRestarts') == 1

# --- Test Log Fetching (No change needed) ---
@pytest.mark.skipif(not health.HAS_NATIVE_JOURNAL, reason="Native systemd bindings not available")
def test_get_unit_logs_native(mock_journal_reader):
     logs = health._get_unit_logs("some.service", num_lines=3)
     assert len(logs) == 3
     assert logs == EXPECTED_NATIVE_LOGS_FORMATTED

# --- Test Main Analysis Logic (Modified to pass units list) ---
@pytest.mark.skipif(not health.HAS_DBUS, reason="DBus bindings not installed")
@patch('sysdiag_analyzer.modules.health._get_unit_logs', return_value=["Mocked log line"])
@patch('sysdiag_analyzer.modules.health.run_subprocess')
def test_analyze_health_dbus_path(mock_run_subprocess_patched, mock_get_logs, mock_dbus_systembus, mock_dbus_interface, mock_units_list): # Add mock_units_list fixture
    """Tests the main health analysis logic using the DBus path."""
    manager_interface = health._get_systemd_manager_interface()
    assert manager_interface is not None
    def run_subprocess_side_effect(command):
        cmd_str = " ".join(command)
        if "systemctl show notfound.service" in cmd_str:
            return (True, MOCK_SYSTEMCTL_SHOW_NOTFOUND, "")
        raise AssertionError(f"run_subprocess unexpectedly called in DBus path: {command}")
    mock_run_subprocess_patched.side_effect = run_subprocess_side_effect

    # Call the function under test, passing the pre-fetched mock unit list
    result = health.analyze_health(units=mock_units_list, dbus_manager=manager_interface)

    assert result.analysis_error is None
    assert result.all_units_count == len(mock_units_list) # Count should match input list
    assert len(result.failed_units) == 1
    assert result.failed_units[0].name == 'failed.service'
    assert result.failed_units[0].details.get('Result') == 'exit-code'
    assert result.failed_units[0].details.get('NRestarts') == 1
    assert len(result.flapping_units) == 1
    assert result.flapping_units[0].name == 'flapping.service'
    assert result.flapping_units[0].details.get('NRestarts') == 5
    assert len(result.problematic_sockets) == 1
    assert result.problematic_sockets[0].name == 'refused.socket'
    assert result.problematic_sockets[0].details.get('Refused') is True
    assert len(result.problematic_timers) == 1
    assert result.problematic_timers[0].name == 'badtimer.timer'
    assert result.problematic_timers[0].details.get('Result') == 'resources'
    assert mock_get_logs.call_count == 4
    assert mock_run_subprocess_patched.call_count == 1 # Only called for notfound.service fallback
    mock_run_subprocess_patched.assert_called_once_with(['systemctl', 'show', 'notfound.service', '--no-pager'])


@patch('sysdiag_analyzer.modules.health.HAS_DBUS', False) # Force fallback
@patch('sysdiag_analyzer.modules.health._get_unit_logs', return_value=["Mocked log line"])
@patch('sysdiag_analyzer.modules.health.run_subprocess')
def test_analyze_health_fallback_path(mock_run_subprocess_patched, mock_get_logs, mock_units_list): # Add mock_units_list fixture
    """Tests the main health analysis logic using the systemctl fallback path."""
    configure_run_subprocess_mock(mock_run_subprocess_patched)

    # Call the function under test, passing the pre-fetched mock unit list
    # DBus manager is None because HAS_DBUS is patched to False
    result = health.analyze_health(units=mock_units_list, dbus_manager=None)

    assert result.analysis_error is None
    assert result.all_units_count == len(mock_units_list) # Count should match input list
    assert len(result.failed_units) == 1
    assert result.failed_units[0].name == 'failed.service'
    assert result.failed_units[0].details.get('Result') == 'exit-code'
    assert len(result.flapping_units) == 1
    assert result.flapping_units[0].name == 'flapping.service'
    assert result.flapping_units[0].details.get('NRestarts') == '5'
    assert len(result.problematic_sockets) == 1
    assert result.problematic_sockets[0].name == 'refused.socket'
    assert result.problematic_sockets[0].details.get('Refused') == 'yes'
    assert len(result.problematic_timers) == 1
    assert result.problematic_timers[0].name == 'badtimer.timer'
    assert result.problematic_timers[0].details.get('Result') == 'resources'
    assert mock_get_logs.call_count == 4
    calls = mock_run_subprocess_patched.call_args_list
    # Check *only* systemctl show calls (list-units is no longer called inside analyze_health)
    assert not any("systemctl list-units" in " ".join(c.args[0]) for c in calls if c.args)
    assert any("systemctl show failed.service" in " ".join(c.args[0]) for c in calls if c.args)
    assert any("systemctl show flapping.service" in " ".join(c.args[0]) for c in calls if c.args)
    assert any("systemctl show refused.socket" in " ".join(c.args[0]) for c in calls if c.args)
    assert any("systemctl show badtimer.timer" in " ".join(c.args[0]) for c in calls if c.args)


# --- Test Overall Error Handling ---
def test_analyze_health_empty_unit_list():
     """Tests when the initial unit listing fails (empty list passed)."""
     result = health.analyze_health(units=[], dbus_manager=None)
     assert result.analysis_error == "No systemd units provided for analysis."
     assert result.all_units_count == 0
     assert len(result.failed_units) == 0
