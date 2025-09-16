import pytest
import logging # <-- Import added
from unittest.mock import patch, MagicMock

# Module to test
from sysdiag_analyzer.modules import dependencies
from sysdiag_analyzer.datatypes import UnitHealthInfo, DependencyAnalysisResult, DependencyInfo

# Conditional DBus imports for potential future tests
try:
    import dbus
    import dbus.exceptions
    HAS_DBUS_FOR_TESTS = True
    MockDBusException = dbus.exceptions.DBusException
except ImportError:
    HAS_DBUS_FOR_TESTS = False
    # Define dummy exception for patching if dbus is not installed
    class MockDBusException(Exception):
        _dbus_error_name = "MockDBusError"
    dbus = MagicMock() # Mock the module itself
    dbus.exceptions = MagicMock()
    dbus.exceptions.DBusException = MockDBusException

# --- Mock Data ---

MOCK_FAILED_UNIT_1 = UnitHealthInfo(name="failedA.service", path="/org/freedesktop/systemd1/unit/failedA_2eservice", is_failed=True)
MOCK_FAILED_UNIT_2 = UnitHealthInfo(name="failedB.service", path="/org/freedesktop/systemd1/unit/failedB_2eservice", is_failed=True)
MOCK_FAILED_UNIT_NO_DEPS = UnitHealthInfo(name="failedC_nodeps.service", path="/org/freedesktop/systemd1/unit/failedC_5fnodeps_2eservice", is_failed=True)
MOCK_FAILED_UNIT_FETCH_ERROR = UnitHealthInfo(name="failedD_fetcherror.service", path="/org/freedesktop/systemd1/unit/failedD_5ffetcherror_2eservice", is_failed=True)

# Mock systemctl show output for _get_unit_properties_fallback
MOCK_SHOW_FAILED_A = """
Id=failedA.service
Requires=req1.service req2.target
Wants=want1.service
After=network.target req1.service
"""
MOCK_SHOW_FAILED_B = """
Id=failedB.service
Requires=req3.service
BindsTo=bind1.service
Before=other.service
"""
MOCK_SHOW_FAILED_C = """
Id=failedC_nodeps.service
Description=No deps here
"""
# Mock systemctl show output for _get_dependency_state fallback
MOCK_SHOW_REQ1_ACTIVE = "Id=req1.service\nLoadState=loaded\nActiveState=active\nSubState=running"
MOCK_SHOW_REQ2_FAILED = "Id=req2.target\nLoadState=loaded\nActiveState=failed\nSubState=failed"
MOCK_SHOW_WANT1_INACTIVE = "Id=want1.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead"
MOCK_SHOW_REQ3_NOTFOUND = "Id=req3.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead" # Simulate not found
MOCK_SHOW_BIND1_ACTIVE = "Id=bind1.service\nLoadState=loaded\nActiveState=active\nSubState=running"

# --- Fixtures ---

@pytest.fixture
def mock_dbus_manager_dep():
    """Provides a basic mock DBus manager object (no methods mocked yet)."""
    if not HAS_DBUS_FOR_TESTS:
        yield None
        return
    mock_manager = MagicMock()
    mock_manager.bus = MagicMock(spec=dbus.SystemBus if HAS_DBUS_FOR_TESTS else object)
    yield mock_manager

@pytest.fixture
def mock_get_unit_properties_fallback_dep():
    """Mocks dependencies._get_unit_properties_fallback."""
    # Use the actual fallback from health module if available, otherwise mock
    try:
        from sysdiag_analyzer.modules.health import _get_unit_properties_fallback as actual_fallback
        patch_target = 'sysdiag_analyzer.modules.dependencies._get_unit_properties_fallback'
    except ImportError:
        # If health module isn't available during test setup, mock directly
        patch_target = 'sysdiag_analyzer.modules.dependencies._get_unit_properties_fallback'

    with patch(patch_target) as mock_fallback:
        def side_effect(unit_name):
            if unit_name == "failedA.service":
                # Simulate parsing key=value output
                props = {}
                for line in MOCK_SHOW_FAILED_A.strip().splitlines():
                    if "=" in line:
                        key, value = line.split("=", 1)
                        props[key.strip()] = value.strip()
                return props
            elif unit_name == "failedB.service":
                props = {}
                for line in MOCK_SHOW_FAILED_B.strip().splitlines():
                    if "=" in line:
                        key, value = line.split("=", 1)
                        props[key.strip()] = value.strip()
                return props
            elif unit_name == "failedC_nodeps.service":
                props = {}
                for line in MOCK_SHOW_FAILED_C.strip().splitlines():
                    if "=" in line:
                        key, value = line.split("=", 1)
                        props[key.strip()] = value.strip()
                return props
            elif unit_name == "failedD_fetcherror.service":
                return None # Simulate failure to fetch props for the failed unit itself
            # Simulate fetching props for *dependency* units within _get_dependency_state
            elif unit_name == "req1.service":
                props = {}
                for line in MOCK_SHOW_REQ1_ACTIVE.strip().splitlines():
                    if "=" in line: key, value = line.split("=", 1); props[key.strip()] = value.strip()
                return props
            elif unit_name == "req2.target":
                props = {}
                for line in MOCK_SHOW_REQ2_FAILED.strip().splitlines():
                     if "=" in line: key, value = line.split("=", 1); props[key.strip()] = value.strip()
                return props
            elif unit_name == "want1.service":
                props = {}
                for line in MOCK_SHOW_WANT1_INACTIVE.strip().splitlines():
                     if "=" in line: key, value = line.split("=", 1); props[key.strip()] = value.strip()
                return props
            elif unit_name == "req3.service":
                # Simulate "not found" - _get_unit_properties_fallback returns None
                return None
            elif unit_name == "bind1.service":
                props = {}
                for line in MOCK_SHOW_BIND1_ACTIVE.strip().splitlines():
                     if "=" in line: key, value = line.split("=", 1); props[key.strip()] = value.strip()
                return props
            elif unit_name == "dep_fetch_error.service":
                 # Simulate failure fetching dependency props
                 return None
            else:
                return None # Default fallback
        mock_fallback.side_effect = side_effect
        yield mock_fallback

# --- Test _get_dependency_state ---

@patch('sysdiag_analyzer.modules.dependencies._get_unit_properties_fallback')
def test_get_dependency_state_fallback_active(mock_props_fallback):
    mock_props_fallback.return_value = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
    load, active, sub, error = dependencies._get_dependency_state("req1.service", None)
    assert load == "loaded"
    assert active == "active"
    assert sub == "running"
    assert error is None
    mock_props_fallback.assert_called_once_with("req1.service")

@patch('sysdiag_analyzer.modules.dependencies._get_unit_properties_fallback')
def test_get_dependency_state_fallback_failed(mock_props_fallback):
    mock_props_fallback.return_value = {"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed"}
    load, active, sub, error = dependencies._get_dependency_state("req2.target", None)
    assert load == "loaded"
    assert active == "failed"
    assert sub == "failed"
    assert error is None
    mock_props_fallback.assert_called_once_with("req2.target")

@patch('sysdiag_analyzer.modules.dependencies._get_unit_properties_fallback')
def test_get_dependency_state_fallback_inactive(mock_props_fallback):
    mock_props_fallback.return_value = {"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead"}
    load, active, sub, error = dependencies._get_dependency_state("want1.service", None)
    assert load == "loaded"
    assert active == "inactive"
    assert sub == "dead"
    assert error is None
    mock_props_fallback.assert_called_once_with("want1.service")

@patch('sysdiag_analyzer.modules.dependencies._get_unit_properties_fallback')
def test_get_dependency_state_fallback_not_found(mock_props_fallback):
    # Simulate _get_unit_properties_fallback returning None (e.g., systemctl show failed)
    mock_props_fallback.return_value = None

    load, active, sub, error = dependencies._get_dependency_state("req3.service", None)

    # Assert the actual behavior: states are None, error is reported
    assert load is None
    assert active is None
    assert sub is None
    assert error == "Failed to get properties for dependency 'req3.service' via fallback."
    mock_props_fallback.assert_called_once_with("req3.service")


@patch('sysdiag_analyzer.modules.dependencies._get_unit_properties_fallback')
def test_get_dependency_state_fallback_cmd_fail(mock_props_fallback):
    # Simulate _get_unit_properties_fallback returning None
    mock_props_fallback.return_value = None

    load, active, sub, error = dependencies._get_dependency_state("dep_fetch_error.service", None)

    assert load is None
    assert active is None
    assert sub is None
    assert error == "Failed to get properties for dependency 'dep_fetch_error.service' via fallback."
    mock_props_fallback.assert_called_once_with("dep_fetch_error.service")


# --- Test _is_dependency_problematic ---

@pytest.mark.parametrize("dep_type, load_state, active_state, sub_state, expected", [
    # Requires (Strong)
    ("Requires", "loaded", "failed", "failed", True),
    ("Requires", "loaded", "inactive", "dead", True),
    ("Requires", "loaded", "inactive", "exited", True), # inactive is problematic
    ("Requires", "not-found", "inactive", "dead", True), # not-found is problematic
    ("Requires", None, None, None, True), # Unknown state is problematic
    ("Requires", "loaded", "active", "running", False),
    ("Requires", "loaded", "activating", "start", False), # Activating is not (yet) problematic
    # BindsTo (Strong)
    ("BindsTo", "loaded", "failed", "failed", True),
    ("BindsTo", "loaded", "inactive", "dead", True),
    ("BindsTo", "not-found", "inactive", "dead", True),
    ("BindsTo", None, None, None, True),
    ("BindsTo", "loaded", "active", "running", False),
    # Wants (Weak)
    ("Wants", "loaded", "failed", "failed", True), # Only failed state is problematic for Wants
    ("Wants", "loaded", "inactive", "dead", False),
    ("Wants", "not-found", "inactive", "dead", False), # not-found Wants is usually ok
    ("Wants", None, None, None, False), # Unknown state for Wants is not problematic
    ("Wants", "loaded", "active", "running", False),
    # Ordering
    ("Before", "loaded", "failed", "failed", False), # Ordering deps aren't considered problematic state causes
    ("After", "loaded", "inactive", "dead", False),
    ("After", "not-found", "inactive", "dead", False),
    ("After", None, None, None, False),
    ("After", "loaded", "active", "running", False),
    # Other
    ("PartOf", "loaded", "failed", "failed", True), # PartOf implies strong link
    ("ConsistsOf", "loaded", "inactive", "dead", True), # ConsistsOf implies strong link
])
def test_is_dependency_problematic(dep_type, load_state, active_state, sub_state, expected):
    dep_info = DependencyInfo(
        name=f"{dep_type.lower()}_dep.service",
        type=dep_type,
        current_load_state=load_state,
        current_active_state=active_state,
        current_sub_state=sub_state
    )
    assert dependencies._is_dependency_problematic(dep_info) == expected

# --- Test analyze_dependencies (Orchestrator) ---

@patch('sysdiag_analyzer.modules.dependencies._get_dependency_state')
def test_analyze_dependencies_success_fallback(mock_get_state, mock_get_unit_properties_fallback_dep, mock_dbus_manager_dep):
    # Configure mock for _get_dependency_state
    def get_state_side_effect(dep_name, dbus_manager):
        if dep_name == "req1.service": return ("loaded", "active", "running", None)
        if dep_name == "req2.target": return ("loaded", "failed", "failed", None)
        if dep_name == "want1.service": return ("loaded", "inactive", "dead", None)
        if dep_name == "network.target": return ("loaded", "active", "running", None)
        if dep_name == "req3.service": return (None, None, None, "Failed to get props") # Simulate not found/error
        if dep_name == "bind1.service": return ("loaded", "active", "running", None)
        if dep_name == "other.service": return ("loaded", "active", "running", None)
        return ("unknown", "unknown", "unknown", "Mock state not defined") # Default fallback
    mock_get_state.side_effect = get_state_side_effect

    failed_units = [MOCK_FAILED_UNIT_1, MOCK_FAILED_UNIT_2]
    result = dependencies.analyze_dependencies(failed_units, mock_dbus_manager_dep)

    assert isinstance(result, DependencyAnalysisResult)
    assert result.analysis_error is None
    assert len(result.failed_unit_dependencies) == 2

    # Check failedA.service results
    info_a = next(fud for fud in result.failed_unit_dependencies if fud.unit_name == "failedA.service")
    assert info_a.error is None
    assert len(info_a.dependencies) == 4 # req1, req2, want1, network.target (After doesn't add network.target again)
    dep_a_map = {d.name: d for d in info_a.dependencies}
    assert "req1.service" in dep_a_map
    assert dep_a_map["req1.service"].type in ["Requires", "After"] # Could be either from mock
    assert dep_a_map["req1.service"].current_active_state == "active"
    assert not dep_a_map["req1.service"].is_problematic
    assert "req2.target" in dep_a_map
    assert dep_a_map["req2.target"].type == "Requires"
    assert dep_a_map["req2.target"].current_active_state == "failed"
    assert dep_a_map["req2.target"].is_problematic
    assert "want1.service" in dep_a_map
    assert dep_a_map["want1.service"].type == "Wants"
    assert dep_a_map["want1.service"].current_active_state == "inactive"
    assert not dep_a_map["want1.service"].is_problematic # Inactive Wants is not problematic
    assert "network.target" in dep_a_map
    assert dep_a_map["network.target"].type == "After"
    assert dep_a_map["network.target"].current_active_state == "active"
    assert not dep_a_map["network.target"].is_problematic

    # Check failedB.service results
    info_b = next(fud for fud in result.failed_unit_dependencies if fud.unit_name == "failedB.service")
    assert info_b.error is None
    assert len(info_b.dependencies) == 3 # req3, bind1, other
    dep_b_map = {d.name: d for d in info_b.dependencies}
    assert "req3.service" in dep_b_map
    assert dep_b_map["req3.service"].type == "Requires"
    assert dep_b_map["req3.service"].current_load_state is None # State fetch failed
    assert dep_b_map["req3.service"].current_active_state is None
    assert dep_b_map["req3.service"].is_problematic # Requires unknown state is problematic
    assert "bind1.service" in dep_b_map
    assert dep_b_map["bind1.service"].type == "BindsTo"
    assert dep_b_map["bind1.service"].current_active_state == "active"
    assert not dep_b_map["bind1.service"].is_problematic
    assert "other.service" in dep_b_map
    assert dep_b_map["other.service"].type == "Before"
    assert dep_b_map["other.service"].current_active_state == "active"
    assert not dep_b_map["other.service"].is_problematic

    # Check mocks called
    assert mock_get_unit_properties_fallback_dep.call_count == 2 # Once for each failed unit
    assert mock_get_state.call_count == 7 # 4 deps for A + 3 deps for B

@patch('sysdiag_analyzer.modules.dependencies._get_dependency_state')
def test_analyze_dependencies_no_deps_found(mock_get_state, mock_get_unit_properties_fallback_dep, mock_dbus_manager_dep):
    failed_units = [MOCK_FAILED_UNIT_NO_DEPS]
    result = dependencies.analyze_dependencies(failed_units, mock_dbus_manager_dep)

    assert result.analysis_error is None
    assert len(result.failed_unit_dependencies) == 1
    info_c = result.failed_unit_dependencies[0]
    assert info_c.unit_name == "failedC_nodeps.service"
    assert info_c.error is None
    assert len(info_c.dependencies) == 0 # Should be empty
    mock_get_unit_properties_fallback_dep.assert_called_once_with("failedC_nodeps.service")
    mock_get_state.assert_not_called() # No deps to check state for

@patch('sysdiag_analyzer.modules.dependencies._get_dependency_state')
def test_analyze_dependencies_fetch_error(mock_get_state, mock_get_unit_properties_fallback_dep, mock_dbus_manager_dep):
    failed_units = [MOCK_FAILED_UNIT_FETCH_ERROR]
    result = dependencies.analyze_dependencies(failed_units, mock_dbus_manager_dep)

    assert result.analysis_error is None # Overall analysis didn't fail
    assert len(result.failed_unit_dependencies) == 1
    info_d = result.failed_unit_dependencies[0]
    assert info_d.unit_name == "failedD_fetcherror.service"
    assert info_d.error == "Failed to get properties for failedD_fetcherror.service to check dependencies."
    assert len(info_d.dependencies) == 0
    mock_get_unit_properties_fallback_dep.assert_called_once_with("failedD_fetcherror.service")
    mock_get_state.assert_not_called()

@patch('sysdiag_analyzer.modules.dependencies._get_dependency_state')
def test_analyze_dependencies_dep_state_error(mock_get_state, mock_get_unit_properties_fallback_dep, mock_dbus_manager_dep, caplog):
    # Configure mock for _get_dependency_state to fail for one dep
    def get_state_side_effect(dep_name, dbus_manager):
        if dep_name == "req1.service": return ("loaded", "active", "running", None)
        if dep_name == "req2.target": return (None, None, None, "Mock DBus Timeout") # Error case
        if dep_name == "want1.service": return ("loaded", "inactive", "dead", None)
        if dep_name == "network.target": return ("loaded", "active", "running", None)
        return ("unknown", "unknown", "unknown", "Mock state not defined")
    mock_get_state.side_effect = get_state_side_effect

    failed_units = [MOCK_FAILED_UNIT_1]
    # Enable logging capture for the specific logger
    with caplog.at_level(logging.WARNING, logger='sysdiag_analyzer.modules.dependencies'): # Use logging.WARNING
        result = dependencies.analyze_dependencies(failed_units, mock_dbus_manager_dep)

    assert result.analysis_error is None
    assert len(result.failed_unit_dependencies) == 1
    info_a = result.failed_unit_dependencies[0]
    assert info_a.error is None # Error was fetching dep state, not the unit itself
    assert len(info_a.dependencies) == 4

    dep_a_map = {d.name: d for d in info_a.dependencies}
    assert "req1.service" in dep_a_map
    assert dep_a_map["req1.service"].current_active_state == "active"
    assert "req2.target" in dep_a_map
    assert dep_a_map["req2.target"].current_active_state is None # State fetch failed
    assert dep_a_map["req2.target"].is_problematic # Unknown state for Requires is problematic
    assert "want1.service" in dep_a_map
    assert dep_a_map["want1.service"].current_active_state == "inactive"

    # Check log message (Now logged by analyze_dependencies)
    assert "Error getting state for dependency 'req2.target' of 'failedA.service': Mock DBus Timeout" in caplog.text
    assert mock_get_state.call_count == 4

def test_analyze_dependencies_empty_input(mock_dbus_manager_dep):
    result = dependencies.analyze_dependencies([], mock_dbus_manager_dep)
    assert result.analysis_error is None
    assert len(result.failed_unit_dependencies) == 0
