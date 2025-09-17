# tests/modules/test_dependencies_graph.py
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import patch, MagicMock

# Conditional import for networkx
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None # Placeholder

# Module to test
from sysdiag_analyzer.modules import dependencies
from sysdiag_analyzer.datatypes import FullDependencyAnalysisResult

# --- Mock Data ---

MOCK_SYSTEMCTL_DEPS_OUTPUT_GOOD = """
unitA.service
● ├─depB.service
● └─depC.target
unitB.service
● └─depD.service
unitC.service
unitD.service
● └─unitA.service
unitE.service
  └─ unitF.service
unitF.service
"""

EXPECTED_DEPS_DATA_GOOD = {
    'unitA.service': {'Requires': ['depB.service', 'depC.target']},
    'unitB.service': {'Requires': ['depD.service']},
    'unitC.service': {}, # Empty dict, not missing key
    'unitD.service': {'Requires': ['unitA.service']},
    'unitE.service': {'Requires': ['unitF.service']}, # Parser assumes Requires, strips chars
    'unitF.service': {}, # Empty dict
}


MOCK_SYSTEMCTL_DEPS_OUTPUT_EMPTY = ""
MOCK_SYSTEMCTL_DEPS_OUTPUT_NO_DEPS = """
unitA.service
unitB.service
unitC.service
"""
MOCK_SYSTEMCTL_DEPS_OUTPUT_MALFORMED = """
● depB.service
unitA.service
● └─depC.service
"""
EXPECTED_DEPS_DATA_MALFORMED = {
    'unitA.service': {'Requires': ['depC.service']},
    # depB.service is skipped because it appeared before unitA, so it's not in the dict
}

# --- Fixtures ---

@pytest.fixture
def mock_run_subprocess_graph():
    """Mocks dependencies.run_subprocess for graph tests."""
    with patch('sysdiag_analyzer.modules.dependencies.run_subprocess') as mock_run:
        # Default to good output
        mock_run.return_value = (True, MOCK_SYSTEMCTL_DEPS_OUTPUT_GOOD, "")
        yield mock_run

# --- Tests for _fetch_all_dependencies_fallback ---

def test_fetch_all_deps_fallback_success(mock_run_subprocess_graph):
    """Test successful parsing of mock systemctl list-dependencies output."""
    deps, error = dependencies._fetch_all_dependencies_fallback()
    assert error is None
    assert deps == EXPECTED_DEPS_DATA_GOOD
    expected_cmd = ["systemctl", "list-dependencies", "--all", "--no-legend", "--no-pager"]
    mock_run_subprocess_graph.assert_called_once_with(expected_cmd)

def test_fetch_all_deps_fallback_empty_output(mock_run_subprocess_graph):
    """Test handling of empty output from the command."""
    mock_run_subprocess_graph.return_value = (True, MOCK_SYSTEMCTL_DEPS_OUTPUT_EMPTY, "")
    deps, error = dependencies._fetch_all_dependencies_fallback()
    assert error is None
    assert deps == {} # Expect empty dict for empty output

def test_fetch_all_deps_fallback_no_deps_output(mock_run_subprocess_graph):
    """Test parsing output with units that have no dependencies."""
    mock_run_subprocess_graph.return_value = (True, MOCK_SYSTEMCTL_DEPS_OUTPUT_NO_DEPS, "")
    deps, error = dependencies._fetch_all_dependencies_fallback()
    assert error is None
    assert deps == {'unitA.service': {}, 'unitB.service': {}, 'unitC.service': {}}

def test_fetch_all_deps_fallback_command_failure(mock_run_subprocess_graph):
    """Test handling of command failure."""
    mock_run_subprocess_graph.return_value = (False, "", "Mock systemctl error")
    deps, error = dependencies._fetch_all_dependencies_fallback()
    assert deps is None
    assert error is not None
    assert "systemctl list-dependencies command failed" in error
    assert "Mock systemctl error" in error

def test_fetch_all_deps_fallback_malformed_output(mock_run_subprocess_graph, caplog):
    """Test parsing output where dependency lines appear before the main unit line."""
    mock_run_subprocess_graph.return_value = (True, MOCK_SYSTEMCTL_DEPS_OUTPUT_MALFORMED, "")
    deps, error = dependencies._fetch_all_dependencies_fallback()
    assert error is None
    assert deps == EXPECTED_DEPS_DATA_MALFORMED
    assert "Skipping dependency line found before any main unit identified" in caplog.text
    assert "'depB.service'" in caplog.text # Check the unit name is in the log

# --- Tests for _build_dependency_graph ---

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
def test_build_graph_success():
    """Test graph creation with valid parsed dependency data."""
    # Use the corrected expected data
    graph, error = dependencies._build_dependency_graph(EXPECTED_DEPS_DATA_GOOD)
    assert error is None
    assert graph is not None
    assert isinstance(graph, nx.DiGraph)
    # Nodes: unitA, B, C, D, E, F, depB, C, D (9 nodes)
    assert graph.number_of_nodes() == 9
    # Edges: A->B, A->C, B->D, D->A, E->F (5 edges) - Type is now Requires for E->F
    assert graph.number_of_edges() == 5
    assert graph.has_edge('unitA.service', 'depB.service')
    assert graph.edges['unitA.service', 'depB.service']['type'] == 'Requires'
    assert graph.has_edge('unitE.service', 'unitF.service')
    assert graph.edges['unitE.service', 'unitF.service']['type'] == 'Requires' # Changed from Wants
    assert graph.has_edge('unitD.service', 'unitA.service') # Cycle edge

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
def test_build_graph_empty_data():
    """Test graph creation with empty dependency data."""
    graph, error = dependencies._build_dependency_graph({})
    assert error is None
    assert graph is not None
    assert graph.number_of_nodes() == 0
    assert graph.number_of_edges() == 0

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
def test_build_graph_missing_target(caplog):
    """Test handling of dependency targets that are not present as source units."""
    mock_data = {'unitA': {'Requires': ['depX']}} # depX is not a key
    graph, error = dependencies._build_dependency_graph(mock_data)
    assert error is None
    assert graph is not None
    assert 'unitA' in graph
    assert 'depX' in graph # Node should still be added
    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1 # Edge should be added if node exists

@patch('sysdiag_analyzer.modules.dependencies.HAS_NETWORKX', False)
@patch('sysdiag_analyzer.modules.dependencies.nx', None)
def test_build_graph_no_networkx():
    """Test the case where networkx is not installed."""
    graph, error = dependencies._build_dependency_graph(EXPECTED_DEPS_DATA_GOOD)
    assert graph is None
    assert error == "networkx library is not installed."

# --- Tests for _find_cycles ---

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
def test_find_cycles_present():
    """Test cycle detection on a mock graph known to contain cycles."""
    graph = nx.DiGraph()
    graph.add_edges_from([
        ('A', 'B'), ('B', 'C'), ('C', 'A'), # Cycle 1
        ('D', 'E'), ('E', 'D'),             # Cycle 2
        ('F', 'G'), ('G', 'H')              # No cycle
    ])
    cycles = dependencies._find_cycles(graph)
    # Convert to set of frozensets for order-independent comparison
    cycle_sets = set(frozenset(c) for c in cycles)
    expected_sets = {frozenset(['A', 'B', 'C']), frozenset(['D', 'E'])}
    assert cycle_sets == expected_sets

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
def test_find_cycles_absent():
    """Test cycle detection on a mock graph with no cycles (DAG)."""
    graph = nx.DiGraph()
    graph.add_edges_from([('A', 'B'), ('B', 'C'), ('A', 'C')])
    cycles = dependencies._find_cycles(graph)
    assert cycles == []

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
def test_find_cycles_empty_graph():
    """Test cycle detection on an empty graph."""
    graph = nx.DiGraph()
    cycles = dependencies._find_cycles(graph)
    assert cycles == []

@patch('sysdiag_analyzer.modules.dependencies.HAS_NETWORKX', False)
@patch('sysdiag_analyzer.modules.dependencies.nx', None)
def test_find_cycles_no_networkx(caplog):
    """Test the case where networkx is not installed."""
    # Pass a dummy graph object, it won't be used due to the HAS_NETWORKX check
    dummy_graph = MagicMock()
    cycles = dependencies._find_cycles(dummy_graph)
    assert cycles == []
    assert "Cannot find cycles, networkx is not available." in caplog.text

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
@patch('networkx.simple_cycles', side_effect=Exception("Mock NX Error"))
def test_find_cycles_exception(mock_simple_cycles, caplog):
    """Test exception handling within nx.simple_cycles()."""
    graph = nx.DiGraph()
    graph.add_edge('A', 'A') # Simple cycle to trigger call
    cycles = dependencies._find_cycles(graph)
    assert cycles == []
    assert "Error during cycle detection: Mock NX Error" in caplog.text

# --- Tests for analyze_full_dependency_graph ---

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
@patch('sysdiag_analyzer.modules.dependencies._find_cycles')
@patch('sysdiag_analyzer.modules.dependencies._build_dependency_graph')
@patch('sysdiag_analyzer.modules.dependencies._fetch_all_dependencies_fallback')
def test_analyze_full_graph_success(mock_fetch, mock_build, mock_find):
    """Test the successful orchestration."""
    # Use corrected expected data
    mock_fetch.return_value = (EXPECTED_DEPS_DATA_GOOD, None)
    mock_graph = nx.DiGraph() # Dummy graph object
    mock_graph.add_edges_from([('D.service','unitA.service'), ('unitA.service','depB.service')]) # Add some edges for realism
    mock_build.return_value = (mock_graph, None)
    # Example cycle based on corrected data
    mock_cycles = [['unitA.service', 'unitD.service']]
    mock_find.return_value = mock_cycles

    result = dependencies.analyze_full_dependency_graph()

    assert isinstance(result, FullDependencyAnalysisResult)
    assert result.analysis_error is None
    assert result.dependency_fetch_error is None
    assert result.graph_build_error is None
    assert result.detected_cycles == mock_cycles
    mock_fetch.assert_called_once()
    mock_build.assert_called_once_with(EXPECTED_DEPS_DATA_GOOD)
    mock_find.assert_called_once_with(mock_graph)

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
@patch('sysdiag_analyzer.modules.dependencies._find_cycles')
@patch('sysdiag_analyzer.modules.dependencies._build_dependency_graph')
@patch('sysdiag_analyzer.modules.dependencies._fetch_all_dependencies_fallback')
def test_analyze_full_graph_fetch_failure(mock_fetch, mock_build, mock_find):
    """Test handling of fetch failure."""
    mock_fetch.return_value = (None, "Fetch Error")

    result = dependencies.analyze_full_dependency_graph()

    assert result.analysis_error == "Failed to fetch full dependency list."
    assert result.dependency_fetch_error == "Fetch Error"
    assert result.graph_build_error is None
    assert result.detected_cycles == []
    mock_fetch.assert_called_once()
    mock_build.assert_not_called()
    mock_find.assert_not_called()

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
@patch('sysdiag_analyzer.modules.dependencies._find_cycles')
@patch('sysdiag_analyzer.modules.dependencies._build_dependency_graph')
@patch('sysdiag_analyzer.modules.dependencies._fetch_all_dependencies_fallback')
def test_analyze_full_graph_build_failure(mock_fetch, mock_build, mock_find):
    """Test handling of graph build failure."""
    mock_fetch.return_value = (EXPECTED_DEPS_DATA_GOOD, None)
    mock_build.return_value = (None, "Build Error")

    result = dependencies.analyze_full_dependency_graph()

    assert result.analysis_error == "Failed to build dependency graph."
    assert result.dependency_fetch_error is None
    assert result.graph_build_error == "Build Error"
    assert result.detected_cycles == []
    mock_fetch.assert_called_once()
    mock_build.assert_called_once_with(EXPECTED_DEPS_DATA_GOOD)
    mock_find.assert_not_called()

@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
@pytest.mark.needs_networkx
@patch('sysdiag_analyzer.modules.dependencies._find_cycles')
@patch('sysdiag_analyzer.modules.dependencies._build_dependency_graph')
@patch('sysdiag_analyzer.modules.dependencies._fetch_all_dependencies_fallback')
def test_analyze_full_graph_empty_data(mock_fetch, mock_build, mock_find):
    """Test handling of empty dependency data."""
    mock_fetch.return_value = ({}, None) # Empty dict, no error
    # Mock build to return an empty graph
    mock_empty_graph = nx.DiGraph()
    mock_build.return_value = (mock_empty_graph, None)
    mock_find.return_value = [] # Expect no cycles

    result = dependencies.analyze_full_dependency_graph()

    assert result.analysis_error is None
    assert result.dependency_fetch_error is None
    assert result.graph_build_error is None
    assert result.detected_cycles == []
    mock_fetch.assert_called_once()
    mock_build.assert_called_once_with({})
    mock_find.assert_called_once_with(mock_empty_graph) # Called with empty graph

@patch('sysdiag_analyzer.modules.dependencies.HAS_NETWORKX', False)
@patch('sysdiag_analyzer.modules.dependencies.nx', None)
@patch('sysdiag_analyzer.modules.dependencies._fetch_all_dependencies_fallback')
def test_analyze_full_graph_no_networkx(mock_fetch):
    """Test the case where networkx is not installed."""
    result = dependencies.analyze_full_dependency_graph()

    assert result.analysis_error == "Optional dependency 'networkx' is not installed. Skipping full graph analysis."
    assert result.dependency_fetch_error is None
    assert result.graph_build_error is None
    assert result.detected_cycles == []
    mock_fetch.assert_not_called() # Should exit early
