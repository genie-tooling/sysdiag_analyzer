# tests/modules/test_resources.py
# -*- coding: utf-8 -*-

import pytest
from pathlib import Path
from typing import Optional # Added List, Dict, Any
from unittest.mock import patch, MagicMock

# Conditional import for dbus
try:
    import dbus
    import dbus.exceptions
    HAS_DBUS_FOR_TESTS = True
except ImportError:
    HAS_DBUS_FOR_TESTS = False
    dbus = MagicMock()
    dbus.exceptions = MagicMock()
# Use a local definition for the mock exception
class MockDBusExceptionForTest(Exception if not HAS_DBUS_FOR_TESTS else dbus.exceptions.DBusException):
    _dbus_error_name: Optional[str] = None
    def __init__(self, message="Mock DBus Error", error_name=None):
        super().__init__(message)
        self._dbus_error_name = error_name if error_name else getattr(super(), '_dbus_error_name', None)
if HAS_DBUS_FOR_TESTS:
    # Ensure the mock exception is used if dbus was imported
    dbus.exceptions.DBusException = MockDBusExceptionForTest

# Modules and datatypes to test
from sysdiag_analyzer.modules import resources
from sysdiag_analyzer.datatypes import (SystemResourceUsage, UnitResourceUsage, UnitHealthInfo, ResourceAnalysisResult)

# --- Mock Data ---
MOCK_CPU_PERCENT = 15.5
MOCK_VIRT_MEM = MagicMock()
MOCK_VIRT_MEM.total = 8 * 1024**3
MOCK_VIRT_MEM.available = 4 * 1024**3
MOCK_VIRT_MEM.percent = 50.0
MOCK_VIRT_MEM.used = 4 * 1024**3
MOCK_VIRT_MEM.free = 3 * 1024**3
MOCK_SWAP_MEM = MagicMock()
MOCK_SWAP_MEM.total = 2 * 1024**3
MOCK_SWAP_MEM.used = 0.5 * 1024**3
MOCK_SWAP_MEM.free = 1.5 * 1024**3
MOCK_SWAP_MEM.percent = 25.0
MOCK_DISK_IO = MagicMock()
MOCK_DISK_IO.read_bytes = 1024*1024*500
MOCK_DISK_IO.write_bytes = 1024*1024*200
MOCK_NET_IO = MagicMock()
MOCK_NET_IO.bytes_sent = 1024*1024*100
MOCK_NET_IO.bytes_recv = 1024*1024*300
MOCK_CPU_STAT_CONTENT = """usage_usec 123456789
user_usec 100000000
system_usec 23456789
nr_periods 0
nr_throttled 0
throttled_usec 0
"""
MOCK_MEM_CURRENT_CONTENT = "104857600" # 100 MiB
MOCK_MEM_PEAK_CONTENT = "157286400" # 150 MiB
MOCK_IO_STAT_CONTENT = """rbytes=52428800 wbytes=10485760 rios=1000 wios=500 dbytes=0 dios=0
""" # 50 MiB read, 10 MiB write (Corrected format)
MOCK_CGROUP_PROCS_CONTENT = """1234
5678
9012
"""
MOCK_CGROUP_PROCS_EMPTY_CONTENT = ""
MOCK_UNIT_INFO_LIST = [
    UnitHealthInfo(name="unitA.service", path="/org/freedesktop/systemd1/unit/unitA_2eservice", details={'MainPID': 1000}),
    UnitHealthInfo(name="unitB.service", path="/org/freedesktop/systemd1/unit/unitB_2eservice", details={'MainPID': 2000}),
    UnitHealthInfo(name="no_cgroup.service", path="/org/freedesktop/systemd1/unit/no_5fcgroup_2eservice"),
    UnitHealthInfo(name="partial_files.service", path="/org/freedesktop/systemd1/unit/partial_5ffiles_2eservice", details={'MainPID': 3000}),
    UnitHealthInfo(name="no_pid_service", path="/org/freedesktop/systemd1/unit/no_pid_service", active_state='active', details={}) # Added unit without PID
]
MOCK_UNIT_USAGE_LIST = [
    UnitResourceUsage(name="high_cpu.service", cpu_usage_nsec=500 * 1e9, memory_current_bytes=100 * 1e6, io_read_bytes=10 * 1e6, io_write_bytes=1 * 1e6),
    UnitResourceUsage(name="high_mem.service", cpu_usage_nsec=50 * 1e9, memory_current_bytes=1000 * 1e6, io_read_bytes=5 * 1e6, io_write_bytes=2 * 1e6),
    UnitResourceUsage(name="high_io.service", cpu_usage_nsec=100 * 1e9, memory_current_bytes=200 * 1e6, io_read_bytes=500 * 1e6, io_write_bytes=100 * 1e6),
    UnitResourceUsage(name="medium.service", cpu_usage_nsec=200 * 1e9, memory_current_bytes=300 * 1e6, io_read_bytes=50 * 1e6, io_write_bytes=10 * 1e6),
    UnitResourceUsage(name="low.service", cpu_usage_nsec=10 * 1e9, memory_current_bytes=50 * 1e6, io_read_bytes=1 * 1e6, io_write_bytes=0),
    UnitResourceUsage(name="no_cpu.service", cpu_usage_nsec=None, memory_current_bytes=60 * 1e6, io_read_bytes=2 * 1e6, io_write_bytes=1 * 1e6),
    UnitResourceUsage(name="no_mem.service", cpu_usage_nsec=20 * 1e9, memory_current_bytes=None, io_read_bytes=3 * 1e6, io_write_bytes=1 * 1e6),
    UnitResourceUsage(name="no_io.service", cpu_usage_nsec=30 * 1e9, memory_current_bytes=70 * 1e6, io_read_bytes=None, io_write_bytes=None),
]

# --- Fixtures ---
@pytest.fixture
def mock_psutil():
    """Mocks relevant psutil functions."""
    with patch('sysdiag_analyzer.modules.resources.psutil.cpu_percent', return_value=MOCK_CPU_PERCENT) as mock_cpu, \
         patch('sysdiag_analyzer.modules.resources.psutil.virtual_memory', return_value=MOCK_VIRT_MEM) as mock_vm, \
         patch('sysdiag_analyzer.modules.resources.psutil.swap_memory', return_value=MOCK_SWAP_MEM) as mock_swap, \
         patch('sysdiag_analyzer.modules.resources.psutil.disk_io_counters', return_value=MOCK_DISK_IO) as mock_disk, \
         patch('sysdiag_analyzer.modules.resources.psutil.net_io_counters', return_value=MOCK_NET_IO) as mock_net:
        yield {
            "cpu": mock_cpu, "vm": mock_vm, "swap": mock_swap,
            "disk": mock_disk, "net": mock_net
        }

@pytest.fixture
def mock_dbus_for_cgroup():
    """
    Mocks DBus interactions for _get_unit_cgroup_path using INTROSPECTION.
    Yields the mocked manager interface and properties interface objects.
    """
    if not HAS_DBUS_FOR_TESTS:
        yield None, None
        return

    mock_bus = MagicMock(spec=dbus.SystemBus if HAS_DBUS_FOR_TESTS else object)
    mock_manager_obj = MagicMock(name="ManagerObjectMock")
    mock_manager_iface = MagicMock(name="ManagerInterfaceMock")
    mock_unit_obj = MagicMock(name="UnitObjectMock")
    # *** CREATE THE MOCK HERE ***
    mock_props_iface = MagicMock(name="PropertiesInterfaceMock")
    mock_manager_iface.bus = mock_bus

    INTROSPECT_XML_SERVICE = """
    <node>
      <interface name="org.freedesktop.systemd1.Service"></interface>
      <interface name="org.freedesktop.DBus.Introspectable"></interface>
    </node>
    """

    def get_object_side_effect(bus_name, object_path):
        if object_path == '/org/freedesktop/systemd1':
            return mock_manager_obj
        mock_unit_obj.object_path = object_path
        return mock_unit_obj
    mock_bus.get_object.side_effect = get_object_side_effect

    def interface_side_effect(dbus_object, interface_name):
        if dbus_object == mock_manager_obj and interface_name == 'org.freedesktop.systemd1.Manager':
            return mock_manager_iface
        if interface_name == 'org.freedesktop.DBus.Introspectable':
            introspect_iface = MagicMock()
            introspect_iface.Introspect.return_value = INTROSPECT_XML_SERVICE
            return introspect_iface
        if interface_name == 'org.freedesktop.DBus.Properties':
            # *** CONFIGURE AND RETURN THE CREATED MOCK ***
            def props_get_side_effect(iface, prop):
                if iface == 'org.freedesktop.systemd1.Service' and prop == 'ControlGroup':
                    return "/system.slice/unitA.service"
                raise MockDBusExceptionForTest("Mock property not found")
            mock_props_iface.Get.side_effect = props_get_side_effect
            return mock_props_iface
        return MagicMock()
    
    mock_interface_class = MagicMock(side_effect=interface_side_effect)

    def get_unit_side_effect(unit_name):
        return f"/org/freedesktop/systemd1/unit/{unit_name.replace('.', '_2e')}"
    mock_manager_iface.GetUnit.side_effect = get_unit_side_effect

    with patch('sysdiag_analyzer.modules.resources.dbus.SystemBus', return_value=mock_bus), \
         patch('sysdiag_analyzer.modules.resources.dbus.Interface', mock_interface_class):
        # *** YIELD BOTH MOCKS SO THE TEST CAN USE THEM ***
        yield mock_manager_iface, mock_props_iface

# --- Tests for System-Wide Usage ---
def test_get_system_wide_usage_success(mock_psutil):
    """Tests successful retrieval of system-wide metrics."""
    result = resources.get_system_wide_usage()

    assert isinstance(result, SystemResourceUsage)
    assert result.error is None
    assert result.cpu_percent == MOCK_CPU_PERCENT
    assert result.mem_total_bytes == MOCK_VIRT_MEM.total
    assert result.mem_available_bytes == MOCK_VIRT_MEM.available
    assert result.mem_percent == MOCK_VIRT_MEM.percent
    assert result.swap_total_bytes == MOCK_SWAP_MEM.total
    assert result.swap_used_bytes == MOCK_SWAP_MEM.used
    assert result.swap_percent == MOCK_SWAP_MEM.percent
    assert result.disk_io_read_bytes == MOCK_DISK_IO.read_bytes
    assert result.disk_io_write_bytes == MOCK_DISK_IO.write_bytes
    assert result.net_io_sent_bytes == MOCK_NET_IO.bytes_sent
    assert result.net_io_recv_bytes == MOCK_NET_IO.bytes_recv

    mock_psutil["cpu"].assert_called_once_with(interval=0.1, percpu=False)
    mock_psutil["vm"].assert_called_once()
    mock_psutil["swap"].assert_called_once()
    mock_psutil["disk"].assert_called_once_with(perdisk=False)
    mock_psutil["net"].assert_called_once_with(pernic=False)

# --- Tests for Cgroup File Reading/Parsing ---
@patch('sysdiag_analyzer.modules.resources.Path.is_file', return_value=True)
@patch('sysdiag_analyzer.modules.resources.Path.read_bytes', return_value=b"file content")
def test_read_cgroup_file_success(mock_read_bytes, mock_is_file):
    """Tests reading a valid cgroup file."""
    test_path = Path("/fake/cgroup/path/file")
    content = resources._read_cgroup_file(test_path)
    assert content == "file content"
    mock_is_file.assert_called_once()
    mock_read_bytes.assert_called_once()

@pytest.mark.parametrize("content, expected_nsec", [
    (MOCK_CPU_STAT_CONTENT, 123456789000),
    ("user_usec 100\nsystem_usec 200", None), # Missing usage_usec
    ("usage_usec not_a_number", None),
    ("", None),
    (None, None),
])
def test_parse_cgroup_cpu_stat(content, expected_nsec, caplog):
    """Tests parsing cpu.stat content."""
    result = resources._parse_cgroup_cpu_stat(content)
    assert result == expected_nsec

# --- Tests for Cgroup Path Lookup ---
@pytest.mark.skipif(not HAS_DBUS_FOR_TESTS, reason="dbus-python not installed")
def test_get_unit_cgroup_path_success(mock_dbus_for_cgroup):
    """Tests successful cgroup path lookup via DBus."""
    manager_iface_mock, props_iface_mock = mock_dbus_for_cgroup
    assert manager_iface_mock is not None # Check fixture success

    path = resources._get_unit_cgroup_path("unitA.service", manager_iface_mock)
    assert path == "system.slice/unitA.service"
    manager_iface_mock.GetUnit.assert_called_once_with('unitA.service')
    props_iface_mock.Get.assert_called_once_with('org.freedesktop.systemd1.Service', 'ControlGroup')

# --- Tests for Per-Unit Usage ---
@patch('sysdiag_analyzer.modules.resources.CGROUP_BASE_PATH', new_callable=MagicMock)
@patch('sysdiag_analyzer.modules.resources.Path')
@patch('sysdiag_analyzer.modules.resources._read_cgroup_file')
@patch('sysdiag_analyzer.modules.resources._get_unit_cgroup_path')
def test_get_unit_resource_usage_success(mock_get_cgroup_path, mock_read_file, mock_path_cls, mock_cgroup_base, mock_dbus_for_cgroup):
    """Tests successful collection of resource usage for multiple units."""
    manager_iface_mock, _ = mock_dbus_for_cgroup
    assert manager_iface_mock is not None

    mock_cgroup_base.is_dir.return_value = True
    mock_cgroup_base.__str__ = lambda self: "/sys/fs/cgroup"

    mock_unit_path_instance = MagicMock(spec=Path)
    mock_cgroup_base.__truediv__.return_value = mock_unit_path_instance
    mock_unit_path_instance.is_dir.return_value = True # Assume unit cgroup dir exists

    def file_path_factory(filename):
        mock_file = MagicMock(spec=Path)
        mock_file.name = filename
        mock_file.is_file.return_value = True
        mock_file.__str__.return_value = f"/sys/fs/cgroup/mock/path/{filename}"
        return mock_file
    mock_unit_path_instance.__truediv__.side_effect = file_path_factory

    current_unit_for_read = None
    def get_path_side_effect(unit_name, dbus_manager):
        assert dbus_manager == manager_iface_mock
        nonlocal current_unit_for_read
        current_unit_for_read = unit_name
        if unit_name == "unitA.service":
            return "system.slice/unitA.service"
        if unit_name == "unitB.service":
            return "user.slice/unitB.service"
        if unit_name == "no_cgroup.service":
            return None
        if unit_name == "partial_files.service":
            return "system.slice/partial_files.service"
        if unit_name == "no_pid_service":
            return "/system.slice/no_pid.service"
        return None
    mock_get_cgroup_path.side_effect = get_path_side_effect

    def read_file_side_effect(path: Path):
        filename = path.name
        unit_context = current_unit_for_read
        if unit_context == "unitA.service":
            if filename == "cpu.stat":
                return MOCK_CPU_STAT_CONTENT
            if filename == "memory.current":
                return MOCK_MEM_CURRENT_CONTENT
            if filename == "memory.peak":
                return MOCK_MEM_PEAK_CONTENT
            if filename == "io.stat":
                return MOCK_IO_STAT_CONTENT
            if filename == "cgroup.procs":
               return MOCK_CGROUP_PROCS_CONTENT
        elif unit_context == "unitB.service":
            if filename == "cpu.stat":
                return "usage_usec 987654321"
            if filename == "memory.current":
               return "209715200"
            if filename == "memory.peak":
               return "209715200"
            if filename == "io.stat":
                return "rbytes=10000 wbytes=20000"
            if filename == "cgroup.procs":
                return "1111\n2222"
        elif unit_context == "partial_files.service":
            if filename == "cpu.stat":
                return MOCK_CPU_STAT_CONTENT
            if filename == "memory.current":
                return MOCK_MEM_CURRENT_CONTENT
            if filename == "memory.peak":
                return MOCK_MEM_PEAK_CONTENT
            if filename == "io.stat":
                return None # Simulate read failure for partial
            if filename == "cgroup.procs":
                return None # Simulate read failure for partial
        elif unit_context == "no_pid_service":
            if filename == "cpu.stat":
               return "usage_usec 50000000"
            return None
        return None
    mock_read_file.side_effect = read_file_side_effect

    # Use the extended MOCK_UNIT_INFO_LIST for this test
    results = resources.get_unit_resource_usage(MOCK_UNIT_INFO_LIST, manager_iface_mock)

    assert len(results) == len(MOCK_UNIT_INFO_LIST)
    unit_a_res = next(r for r in results if r.name == "unitA.service")
    assert unit_a_res.error is None
    assert unit_a_res.cgroup_path == "system.slice/unitA.service"
    assert unit_a_res.cpu_usage_nsec == 123456789000
    assert unit_a_res.memory_current_bytes == 104857600
    assert unit_a_res.memory_peak_bytes == 157286400
    assert unit_a_res.io_read_bytes == 52428800
    assert unit_a_res.io_write_bytes == 10485760
    assert unit_a_res.tasks_current == 3

# --- Tests for Main Orchestrator (modified to pass unit list) ---
@patch('sysdiag_analyzer.modules.resources.get_system_wide_usage')
@patch('sysdiag_analyzer.modules.resources.get_unit_resource_usage')
@patch('sysdiag_analyzer.modules.resources._scan_and_group_child_processes', return_value=[])
@patch('sysdiag_analyzer.modules.resources._get_service_pids') # Keep patching _get_service_pids
def test_analyze_resources_success(mock_get_pids, mock_scan_children, mock_get_unit_usage, mock_get_sys_usage, mock_dbus_for_cgroup):
    """Tests the main analyze_resources orchestrator function successfully."""
    mock_sys_usage_obj = SystemResourceUsage(cpu_percent=10.0, mem_percent=40.0)
    mock_get_sys_usage.return_value = mock_sys_usage_obj
    mock_get_unit_usage.return_value = MOCK_UNIT_USAGE_LIST
    manager_iface_mock, _ = mock_dbus_for_cgroup
    assert manager_iface_mock is not None
    # Configure mock_get_pids based on MOCK_UNIT_INFO_LIST
    mock_pids_return = {
        u.name: u.details.get('MainPID')
        for u in MOCK_UNIT_INFO_LIST
        if u.name.endswith('.service') and u.details.get('MainPID')
    }
    mock_get_pids.return_value = mock_pids_return

    # Call analysis with the mock unit list
    result = resources.analyze_resources(units=MOCK_UNIT_INFO_LIST, dbus_manager=manager_iface_mock)

    assert isinstance(result, ResourceAnalysisResult)
    assert result.analysis_error is None
    assert result.system_usage == mock_sys_usage_obj
    assert result.unit_usage == MOCK_UNIT_USAGE_LIST
    assert result.child_process_groups == []
    # (Top N assertions remain the same)
    expected_cpu_count = len([u for u in MOCK_UNIT_USAGE_LIST if u.cpu_usage_nsec is not None])
    expected_mem_count = len([u for u in MOCK_UNIT_USAGE_LIST if u.memory_current_bytes is not None])
    expected_io_count = len([u for u in MOCK_UNIT_USAGE_LIST if u.io_read_bytes is not None and u.io_write_bytes is not None])
    assert len(result.top_cpu_units) == min(resources.TOP_N_COUNT, expected_cpu_count)
    assert result.top_cpu_units[0].name == "high_cpu.service"
    assert len(result.top_memory_units) == min(resources.TOP_N_COUNT, expected_mem_count)
    assert result.top_memory_units[0].name == "high_mem.service"
    assert len(result.top_io_units) == min(resources.TOP_N_COUNT, expected_io_count)
    assert result.top_io_units[0].name == "high_io.service"
    # Check mocks
    mock_get_sys_usage.assert_called_once()
    mock_get_pids.assert_called_once_with(MOCK_UNIT_INFO_LIST, manager_iface_mock)
    mock_scan_children.assert_called_once_with(mock_pids_return)
    mock_get_unit_usage.assert_called_once_with(MOCK_UNIT_INFO_LIST, manager_iface_mock)


@patch('sysdiag_analyzer.modules.resources.HAS_DBUS', False)
@patch('sysdiag_analyzer.modules.resources.get_system_wide_usage')
@patch('sysdiag_analyzer.modules.resources.get_unit_resource_usage')
@patch('sysdiag_analyzer.modules.resources._scan_and_group_child_processes')
@patch('sysdiag_analyzer.modules.resources._get_service_pids', return_value={})
def test_analyze_resources_no_dbus_module(mock_get_pids, mock_scan_children, mock_get_unit_usage, mock_get_sys_usage):
    """Tests analyze_resources when HAS_DBUS is False."""
    mock_get_sys_usage.return_value = SystemResourceUsage()
    # Call with mock unit list, dbus_manager=None
    result = resources.analyze_resources(units=MOCK_UNIT_INFO_LIST, dbus_manager=None)

    assert result.analysis_error is not None
    assert "DBus bindings not installed" in result.analysis_error
    mock_get_unit_usage.assert_not_called()
    assert result.unit_usage == []
    assert result.top_cpu_units == []
    mock_get_pids.assert_called_once_with(MOCK_UNIT_INFO_LIST, None) # PID lookup still attempted
    mock_scan_children.assert_not_called() # Scan skipped because get_pids returned empty

@patch('sysdiag_analyzer.modules.resources.get_system_wide_usage')
@patch('sysdiag_analyzer.modules.resources.get_unit_resource_usage')
@patch('sysdiag_analyzer.modules.resources._scan_and_group_child_processes')
@patch('sysdiag_analyzer.modules.resources._get_service_pids', return_value={})
def test_analyze_resources_no_units_provided(mock_get_pids, mock_scan_children, mock_get_unit_usage, mock_get_sys_usage, mock_dbus_for_cgroup):
    """Tests analyze_resources when the input unit list is empty."""
    mock_get_sys_usage.return_value = SystemResourceUsage()
    manager_iface_mock, _ = mock_dbus_for_cgroup
    assert manager_iface_mock is not None # Ensure fixture ran

    # Call with empty unit list
    result = resources.analyze_resources(units=[], dbus_manager=manager_iface_mock)

    assert result.analysis_error is not None
    assert "No units provided" in result.analysis_error
    mock_get_unit_usage.assert_not_called()
    assert result.unit_usage == []
    assert result.top_cpu_units == []
    mock_get_pids.assert_called_once_with([], manager_iface_mock) # Called with empty list
    mock_scan_children.assert_not_called() # Scan skipped
