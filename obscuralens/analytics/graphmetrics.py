"""
Graph analytics over investigation entity graphs (v6.0 Part 2).

ObscuraLens already builds entity graphs everywhere: :func:`investigate`
returns ``entities``/``links`` per target, the correlation engine merges
them across the whole history. This module turns those graphs into
measurements an analyst can rank and defend - who is the hub, which
relationship holds two clusters together, how far apart two entities sit -
using nothing but the Python standard library.

Input convention (matches the investigate/correlation payloads):

* **entities** - list of dicts, each carrying ``'id'`` or a
  ``'kind'``/``'type'`` + ``'value'`` pair (the id is then synthesised as
  ``'kind:value'``, exactly the platform's convention).
* **links** - list of dicts with ``'source'``/``'target'`` endpoints (the
  investigate payload's ``'from'``/``'to'`` keys are accepted as synonyms)
  and an optional ``'relation'``/``'label'``.

Everything operates on the undirected adjacency map produced by
:func:`build_adjacency`, so one conversion step feeds every metric.

Design contract (mirrored across the analytics package):

* **Defensive by default.** ``None``, malformed entities, non-string ids
  and dangling link endpoints never raise: unusable items are dropped,
  unknown endpoints are added as nodes, and every function returns a safe
  empty structure for empty input.
* **Deterministic.** Iteration orders are canonical (sorted node ids), so
  the same graph always yields byte-identical reports; the only seeded
  randomness lives in :func:`label_propagation_communities`'s explicit
  ``random.Random(seed)``.
* **Small-graph sized.** Betweenness is skipped above 200 nodes (it is
  O(V*E)) - OSINT graphs are small, and the guard keeps a fat history
  graph from freezing the CLI.
"""

import math
import random
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

__all__ = [
    'betweenness_centrality',
    'bridges',
    'build_adjacency',
    'connected_components',
    'degree_centrality',
    'graph_summary',
    'label_propagation_communities',
    'pagerank',
    'shortest_path',
    'top_entities',
]

#: Node-count ceiling above which :func:`betweenness_centrality` refuses to
#: run (Brandes is O(V*E); a fat merged history graph would stall the CLI).
_BETWEENNESS_MAX_NODES = 200

#: Default damping factor for :func:`pagerank` (the classic 0.85).
_DEFAULT_DAMPING = 0.85

#: Default PageRank iteration budget and convergence tolerance.
_PAGERANK_ITERATIONS = 50
_PAGERANK_TOL = 1e-6

#: Label-propagation defaults: seeded RNG and round budget.
_LABEL_SEED = 7
_LABEL_ITERATIONS = 25


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def _entity_id(entity: Any) -> Optional[str]:
    """Resolve one entity dict to its node id (None when unusable).

    Accepts an ``'id'`` key directly, or synthesises ``'kind:value'`` from
    ``'kind'``/``'type'`` plus ``'value'`` - the same convention the
    investigate and correlation graphs use.
    """
    if not isinstance(entity, dict):
        return None
    identifier = entity.get('id')
    if isinstance(identifier, str) and identifier.strip():
        return identifier
    kind = entity.get('kind') or entity.get('type')
    value = entity.get('value')
    if isinstance(kind, str) and kind.strip() and value is not None:
        text = str(value).strip()
        if text:
            return f'{kind}:{text}'
    return None


def _link_endpoints(link: Any) -> Optional[Tuple[str, str]]:
    """Resolve one link dict to ``(source, target)`` (None when unusable).

    ``'source'``/``'target'`` are canonical; the investigate payload's
    ``'from'``/``'to'`` keys are accepted as synonyms. Self-loops yield
    ``None`` - they add nothing to an undirected adjacency.
    """
    if not isinstance(link, dict):
        return None
    source = link.get('source') or link.get('from')
    target = link.get('target') or link.get('to')
    if not isinstance(source, str) or not isinstance(target, str):
        return None
    source = source.strip()
    target = target.strip()
    if not source or not target or source == target:
        return None
    return source, target


def build_adjacency(entities: Any, links: Any) -> Dict[str, Set[str]]:
    """Build an undirected adjacency map from entity/link payload slices.

    Entities register as nodes even when they have no links (isolated
    nodes matter: they are entities nobody connected yet). Link endpoints
    missing from the entity list are added to the graph anyway - a
    dangling reference is evidence of a relationship, not an error.

    Args:
        entities: Iterable of entity dicts (``'id'`` or ``'kind'``/``'type'``
            + ``'value'``). ``None``, non-dict items and unusable ids are
            dropped silently.
        links: Iterable of link dicts (``'source'``/``'target'`` or
            ``'from'``/``'to'``). Non-dict items and self-loops are dropped.

    Returns:
        Mapping ``node -> set of neighbour nodes`` (undirected, symmetric,
        self-loop free). Empty dict for empty input. Never raises.

    Example:
        >>> adj = build_adjacency([{'id': 'a'}, {'id': 'b'}],
        ...                       [{'source': 'a', 'target': 'b'}])
        >>> adj == {'a': {'b'}, 'b': {'a'}}
        True
    """
    adjacency: Dict[str, Set[str]] = {}
    if entities is not None and not isinstance(entities, (str, bytes)):
        try:
            iterator = iter(entities)
        except TypeError:
            iterator = iter(())
        for entity in iterator:
            identifier = _entity_id(entity)
            if identifier is not None:
                adjacency.setdefault(identifier, set())

    if links is not None and not isinstance(links, (str, bytes)):
        try:
            iterator = iter(links)
        except TypeError:
            iterator = iter(())
        for link in iterator:
            endpoints = _link_endpoints(link)
            if endpoints is None:
                continue
            source, target = endpoints
            adjacency.setdefault(source, set()).add(target)
            adjacency.setdefault(target, set()).add(source)
    return adjacency


def _nodes_of(adjacency: Any) -> List[str]:
    """Every node id in an adjacency map (keys plus stray neighbours), sorted."""
    if not isinstance(adjacency, dict):
        return []
    nodes: Set[str] = set(adjacency)
    for neighbours in adjacency.values():
        if isinstance(neighbours, (set, frozenset, list, tuple)):
            nodes.update(item for item in neighbours if isinstance(item, str))
    return sorted(nodes)


def _neighbors_of(adjacency: Dict[str, Set[str]], node: str) -> List[str]:
    """Sorted neighbour list of one node (empty when unknown or malformed)."""
    raw = adjacency.get(node)
    if not isinstance(raw, (set, frozenset, list, tuple)):
        return []
    return sorted(item for item in raw if isinstance(item, str))


# ---------------------------------------------------------------------------
# Centrality
# ---------------------------------------------------------------------------

def degree_centrality(adjacency: Any) -> Dict[str, float]:
    """Normalised degree centrality of every node.

    The count of a node's relationships divided by the maximum possible
    (``n - 1``) so scores are comparable across graphs of different size.
    For an undirected graph this is the simplest "who is the hub" measure -
    and for OSINT graphs often the most honest one.

    Args:
        adjacency: Adjacency map from :func:`build_adjacency` (anything
            else yields an empty dict).

    Returns:
        Mapping ``node -> centrality`` in ``[0, 1]``; graphs with fewer
        than two nodes score every node 0.0. Never raises.

    Example:
        >>> scores = degree_centrality({'a': {'b', 'c'}, 'b': {'a'}, 'c': {'a'}})
        >>> scores['a']
        1.0
    """
    nodes = _nodes_of(adjacency)
    if not isinstance(adjacency, dict):
        return {}
    count = len(nodes)
    normaliser = count - 1 if count > 1 else 0
    return {node: (len(adjacency.get(node, ())) / normaliser
                   if normaliser > 0 else 0.0)
            for node in nodes}


def pagerank(adjacency: Any, damping: float = 0.85, iterations: int = 50,
             tol: float = 1e-6) -> Dict[str, float]:
    """Classic iterative PageRank over the undirected graph.

    Each round redistributes a node's rank across its neighbours
    (``damping`` fraction flows along links, ``1 - damping`` is the random
    jump). Nodes with no outgoing edges are **dangling**: their entire
    rank is spread uniformly over all nodes, the standard correction
    without which dead ends drain the graph's mass.

    Args:
        adjacency: Adjacency map from :func:`build_adjacency`.
        damping: Jump probability kept, in ``(0, 1]`` (default 0.85;
            non-finite or out-of-range values fall back to the default).
        iterations: Maximum rounds (values below 1 become 1).
        tol: Convergence tolerance on the largest per-node change;
            non-finite or non-positive values fall back to ``1e-6``.

    Returns:
        Mapping ``node -> rank`` (ranks sum to ~1.0). Empty dict for an
        empty graph. Never raises.

    Example:
        >>> ranks = pagerank({'hub': {'a', 'b'}, 'a': {'hub'}, 'b': {'hub'}})
        >>> ranks['hub'] > ranks['a']
        True
    """
    if not isinstance(adjacency, dict):
        return {}
    nodes = _nodes_of(adjacency)
    if not nodes:
        return {}

    factor = _as_float(damping)
    if factor is None or factor <= 0.0 or factor > 1.0:
        factor = _DEFAULT_DAMPING
    rounds = _as_int(iterations, _PAGERANK_ITERATIONS)
    if rounds < 1:
        rounds = 1
    tolerance = _as_float(tol)
    if tolerance is None or tolerance <= 0.0:
        tolerance = _PAGERANK_TOL

    count = len(nodes)
    ranks: Dict[str, float] = dict.fromkeys(nodes, 1.0 / count)
    neighbours = {node: _neighbors_of(adjacency, node) for node in nodes}
    # Undirected graph: in-neighbours are exactly the out-neighbours.
    incoming: Dict[str, List[str]] = {node: [] for node in nodes}
    dangling: List[str] = []
    for node in nodes:
        links_out = neighbours[node]
        if links_out:
            for other in links_out:
                if other in incoming:
                    incoming[other].append(node)
        else:
            dangling.append(node)

    for _round in range(rounds):
        dangling_share = factor * sum(ranks[node] for node in dangling) / count
        base = (1.0 - factor) / count + dangling_share
        updated: Dict[str, float] = {}
        for node in nodes:
            flow = 0.0
            for source in incoming[node]:
                flow += ranks[source] / len(neighbours[source])
            updated[node] = base + factor * flow
        delta = max(abs(updated[node] - ranks[node]) for node in nodes)
        ranks = updated
        if delta < tolerance:
            break

    total = sum(ranks.values())
    if total > 0.0:  # pragma: no branch - mass is conserved by construction
        ranks = {node: value / total for node, value in ranks.items()}
    return ranks


def betweenness_centrality(adjacency: Any) -> Dict[str, float]:
    """Brandes betweenness centrality (nodes skipped above 200 nodes).

    Betweenness counts how many shortest paths pass through a node: the
    broker between clusters, the resolver everyone routes through. The
    Brandes algorithm computes all of them in one dependency-DAG sweep -
    O(V*E) - which is instant for investigation graphs but too slow for a
    fat merged history, so **graphs with more than 200 nodes return an
    empty dict** (callers treat "not measured" as the honest answer
    rather than a hang).

    Args:
        adjacency: Adjacency map from :func:`build_adjacency`.

    Returns:
        Mapping ``node -> normalised betweenness`` in ``[0, 1]``
        (undirected normalisation ``2 / ((n-1)(n-2))``; graphs with fewer
        than three nodes score 0.0 everywhere). Empty dict for empty input
        or above the node ceiling. Never raises.

    Example:
        >>> adj = build_adjacency([{'id': n} for n in 'abcd'],
        ...                       [{'source': 'a', 'target': 'b'},
        ...                        {'source': 'b', 'target': 'c'},
        ...                        {'source': 'c', 'target': 'd'}])
        >>> scores = betweenness_centrality(adj)
        >>> scores['b'] > scores['a']
        True
    """
    if not isinstance(adjacency, dict):
        return {}
    nodes = _nodes_of(adjacency)
    if not nodes or len(nodes) > _BETWEENNESS_MAX_NODES:
        return {}
    counts = len(nodes)

    centrality: Dict[str, float] = dict.fromkeys(nodes, 0.0)
    for start in nodes:
        stack: List[str] = []
        parents: Dict[str, List[str]] = {node: [] for node in nodes}
        path_counts: Dict[str, float] = dict.fromkeys(nodes, 0.0)
        distances: Dict[str, int] = dict.fromkeys(nodes, -1)
        path_counts[start] = 1.0
        distances[start] = 0
        queue: Deque[str] = deque([start])
        while queue:
            node = queue.popleft()
            stack.append(node)
            for neighbour in _neighbors_of(adjacency, node):
                if distances[neighbour] < 0:
                    distances[neighbour] = distances[node] + 1
                    queue.append(neighbour)
                if distances[neighbour] == distances[node] + 1:
                    path_counts[neighbour] += path_counts[node]
                    parents[neighbour].append(node)

        dependencies: Dict[str, float] = dict.fromkeys(nodes, 0.0)
        while stack:
            node = stack.pop()
            for parent in parents[node]:
                share = (path_counts[parent] / path_counts[node]
                         * (1.0 + dependencies[node]))
                dependencies[parent] += share
            if node != start:
                centrality[node] += dependencies[node]

    if counts > 2:
        # Brandes over an undirected graph counts ordered (s, t) pairs, so
        # the raw score is twice the unordered one; dividing by
        # (n-1)(n-2) folds that factor into the classic 2/((n-1)(n-2))
        # undirected normalisation.
        normaliser = 1.0 / ((counts - 1) * (counts - 2))
        centrality = {node: value * normaliser
                      for node, value in centrality.items()}
    else:
        centrality = dict.fromkeys(nodes, 0.0)
    return centrality


# ---------------------------------------------------------------------------
# Structure: components, communities, bridges, paths
# ---------------------------------------------------------------------------

def connected_components(adjacency: Any) -> List[List[str]]:
    """Connected components (BFS), largest first.

    Each component is the set of nodes reachable from one another; an
    investigation graph with many components is many unrelated cases, and
    the component census is the first question an analyst asks.

    Args:
        adjacency: Adjacency map from :func:`build_adjacency`.

    Returns:
        List of node lists sorted by size descending (ties broken by the
        alphabetically first member); members keep BFS discovery order
        from the alphabetically first start node. Never raises.

    Example:
        >>> comps = connected_components({'a': {'b'}, 'b': {'a'}, 'c': set()})
        >>> sorted(comps[0])
        ['a', 'b']
    """
    if not isinstance(adjacency, dict):
        return []
    nodes = _nodes_of(adjacency)
    seen: Set[str] = set()
    components: List[List[str]] = []
    for start in nodes:
        if start in seen:
            continue
        seen.add(start)
        component = [start]
        queue: Deque[str] = deque([start])
        while queue:
            node = queue.popleft()
            for neighbour in _neighbors_of(adjacency, node):
                if neighbour not in seen:
                    seen.add(neighbour)
                    component.append(neighbour)
                    queue.append(neighbour)
        components.append(component)
    components.sort(key=lambda members: (-len(members), members[0]))
    return components


def label_propagation_communities(adjacency: Any, seed: int = 7,
                                  iterations: int = 25) -> List[List[str]]:
    """Label-propagation community detection with seeded tie-breaks.

    Every node starts labelled with itself; each round visits nodes in
    seeded-random order and adopts the most frequent label among its
    neighbours (ties resolved by the seeded RNG). Labels diffuse until the
    labelling stabilises or the round budget runs out, and nodes sharing
    a final label form a community. Cheap, parameter-free, and good
    enough to say "these entities cluster".

    Args:
        adjacency: Adjacency map from :func:`build_adjacency`.
        seed: RNG seed for visit order and tie-breaks (default 7); the
            same graph and seed always produce the same communities.
        iterations: Maximum rounds (values below 1 become 1).

    Returns:
        List of node lists sorted by size descending (ties broken by the
        alphabetically first member). Isolated nodes form singleton
        communities. Empty list for an empty graph. Never raises.

    Example:
        >>> adj = build_adjacency([{'id': n} for n in 'abcd'],
        ...                       [{'source': 'a', 'target': 'b'},
        ...                        {'source': 'c', 'target': 'd'}])
        >>> len(label_propagation_communities(adj))
        2
    """
    if not isinstance(adjacency, dict):
        return []
    nodes = _nodes_of(adjacency)
    if not nodes:
        return []
    rng = random.Random(_as_int(seed, _LABEL_SEED))
    rounds = max(1, _as_int(iterations, _LABEL_ITERATIONS))

    labels: Dict[str, str] = {node: node for node in nodes}
    neighbours = {node: _neighbors_of(adjacency, node) for node in nodes}
    for _round in range(rounds):
        order = list(nodes)
        rng.shuffle(order)
        changed = False
        for node in order:
            if not neighbours[node]:
                continue
            votes: Dict[str, int] = {}
            for neighbour in neighbours[node]:
                label = labels[neighbour]
                votes[label] = votes.get(label, 0) + 1
            best = max(votes.values())
            candidates = sorted(label for label, count in votes.items()
                                if count == best)
            winner = candidates[0] if len(candidates) == 1 else rng.choice(candidates)
            if winner != labels[node]:
                labels[node] = winner
                changed = True
        if not changed:
            break

    communities: Dict[str, List[str]] = {}
    for node in nodes:
        communities.setdefault(labels[node], []).append(node)
    grouped = list(communities.values())
    grouped.sort(key=lambda members: (-len(members), sorted(members)[0]))
    return grouped


def bridges(adjacency: Any) -> List[Tuple[str, str]]:
    """Tarjan bridge edges: relationships whose removal splits the graph.

    A bridge is an edge that is not part of any cycle - delete it and the
    graph gains a component. In an investigation graph that is exactly
    the relationship that holds two clusters together (the one registrar
    link tying a fraud ring to its infrastructure), which makes bridges
    among the highest-value edges to verify and to sever.

    Iterative depth-first implementation (no recursion, so pathologically
    deep graphs cannot hit the interpreter limit).

    Args:
        adjacency: Adjacency map from :func:`build_adjacency`.

    Returns:
        List of ``(u, v)`` tuples (each pair sorted, list sorted overall).
        Empty list when the graph has no bridges or is empty. Never
        raises.

    Example:
        >>> adj = build_adjacency([{'id': n} for n in 'abcd'],
        ...                       [{'source': 'a', 'target': 'b'},
        ...                        {'source': 'b', 'target': 'c'},
        ...                        {'source': 'c', 'target': 'd'}])
        >>> ('b', 'c') in bridges(adj)
        True
    """
    if not isinstance(adjacency, dict):
        return []
    nodes = _nodes_of(adjacency)
    if not nodes:
        return []

    visited: Set[str] = set()
    discovery: Dict[str, int] = {}
    low: Dict[str, int] = {}
    parent: Dict[str, Optional[str]] = {}
    clock = 0
    found: List[Tuple[str, str]] = []

    for start in nodes:
        if start in visited:
            continue
        visited.add(start)
        parent[start] = None
        discovery[start] = low[start] = clock
        clock += 1
        stack: List[Tuple[str, Any]] = [(start, iter(_neighbors_of(adjacency, start)))]
        while stack:
            node, walker = stack[-1]
            descended = False
            for neighbour in walker:
                if neighbour not in visited:
                    visited.add(neighbour)
                    parent[neighbour] = node
                    discovery[neighbour] = low[neighbour] = clock
                    clock += 1
                    stack.append((neighbour, iter(_neighbors_of(adjacency, neighbour))))
                    descended = True
                    break
                if neighbour != parent.get(node) and discovery[neighbour] < discovery[node]:
                    low[node] = min(low[node], discovery[neighbour])
            if not descended:
                stack.pop()
                if stack:
                    above = stack[-1][0]
                    low[above] = min(low[above], low[node])
                    if low[node] > discovery[above]:
                        found.append(tuple(sorted((above, node))))
    found.sort()
    return found


def shortest_path(adjacency: Any, source: Any, target: Any) -> Optional[List[str]]:
    """BFS shortest path between two nodes.

    Answers "how many hops between these two entities" - the distance an
    analyst must traverse to connect a suspect to an infrastructure node.

    Args:
        adjacency: Adjacency map from :func:`build_adjacency`.
        source: Start node id. Unknown or non-string ids yield ``None``.
        target: Goal node id; ``source == target`` yields ``[source]``
            when the node exists.

    Returns:
        Node list from ``source`` to ``target`` inclusive, or ``None``
        when either endpoint is unknown or no path exists. Never raises.

    Example:
        >>> adj = build_adjacency([{'id': n} for n in 'abc'],
        ...                       [{'source': 'a', 'target': 'b'},
        ...                        {'source': 'b', 'target': 'c'}])
        >>> shortest_path(adj, 'a', 'c')
        ['a', 'b', 'c']
    """
    if not isinstance(adjacency, dict):
        return None
    if not isinstance(source, str) or not isinstance(target, str):
        return None
    nodes = set(_nodes_of(adjacency))
    if source not in nodes or target not in nodes:
        return None
    if source == target:
        return [source]

    parents: Dict[str, Optional[str]] = {source: None}
    queue: Deque[str] = deque([source])
    while queue:
        node = queue.popleft()
        for neighbour in _neighbors_of(adjacency, node):
            if neighbour in parents:
                continue
            parents[neighbour] = node
            if neighbour == target:
                path: List[str] = [neighbour]
                step = node
                while step is not None:
                    path.append(step)
                    step = parents[step]
                path.reverse()
                return path
            queue.append(neighbour)
    return None


# ---------------------------------------------------------------------------
# Ranking and one-shot summaries
# ---------------------------------------------------------------------------

def top_entities(adjacency: Any, metric: str = 'degree', top: int = 10
                 ) -> List[Dict[str, Any]]:
    """Rank nodes by a chosen centrality metric.

    One call computes the full metric family (raw degree, degree
    centrality, PageRank, betweenness) and returns the top rows in
    self-documenting form - the table every investigation report wants at
    the top.

    Args:
        adjacency: Adjacency map from :func:`build_adjacency`.
        metric: Sort key, one of ``'degree'`` (default), ``'degree_centrality'``,
            ``'pagerank'`` or ``'betweenness'``; unknown names fall back to
            ``'degree'``.
        top: Maximum rows returned (values below 0 mean 0).

    Returns:
        List of ``{'id', 'degree', 'degree_centrality', 'pagerank',
        'betweenness'}`` dicts sorted by the chosen metric descending,
        ties broken alphabetically. ``betweenness`` is ``None`` for every
        row when the graph exceeds the 200-node ceiling. Never raises.

    Example:
        >>> adj = build_adjacency([{'id': n} for n in 'abc'],
        ...                       [{'source': 'a', 'target': 'b'},
        ...                        {'source': 'a', 'target': 'c'}])
        >>> top_entities(adj)[0]['id']
        'a'
    """
    if not isinstance(adjacency, dict):
        return []
    nodes = _nodes_of(adjacency)
    if not nodes:
        return []
    limit = _as_int(top, 10)
    if limit < 0:
        limit = 0

    degrees = {node: len(adjacency.get(node, ())) for node in nodes}
    centrality = degree_centrality(adjacency)
    ranks = pagerank(adjacency)
    betweenness = betweenness_centrality(adjacency)
    betweenness_missing = not betweenness

    rows: List[Dict[str, Any]] = []
    for node in nodes:
        rows.append({
            'id': node,
            'degree': degrees[node],
            'degree_centrality': centrality.get(node, 0.0),
            'pagerank': ranks.get(node, 0.0),
            'betweenness': None if betweenness_missing
            else betweenness.get(node, 0.0),
        })
    if metric not in ('degree', 'degree_centrality', 'pagerank', 'betweenness'):
        metric = 'degree'

    def sort_key(row: Dict[str, Any]) -> Tuple[float, str]:
        value = row[metric]
        return (-(value if value is not None else 0.0), row['id'])

    rows.sort(key=sort_key)
    return rows[:limit]


def graph_summary(entities: Any, links: Any) -> Dict[str, Any]:
    """One-shot graph dossier: shape, components, communities, bridges.

    The single call the CLI/web/MCP layers make to render a graph
    overview: node and edge counts, density, average degree, component
    census, top degree entities, community count and bridge count.

    Args:
        entities: Entity dicts (see :func:`build_adjacency`).
        links: Link dicts (see :func:`build_adjacency`).

    Returns:
        Dict with keys:

        * ``'node_count'`` / ``'edge_count'`` - graph size (edges counted
          once per unordered pair).
        * ``'density'`` - ``2E / (N(N-1))``, 0.0 for fewer than 2 nodes.
        * ``'avg_degree'`` - ``2E / N``, 0.0 for an empty graph.
        * ``'component_count'`` / ``'largest_component_size'`` - from
          :func:`connected_components`.
        * ``'community_count'`` - from :func:`label_propagation_communities`.
        * ``'top_entities'`` - top 5 by degree (see :func:`top_entities`).
        * ``'bridge_count'`` / ``'bridges'`` - from :func:`bridges`.
        * ``'isolated_nodes'`` - nodes with no relationships.

    Example:
        >>> summary = graph_summary([{'id': 'a'}, {'id': 'b'}, {'id': 'c'}],
        ...                         [{'source': 'a', 'target': 'b'},
        ...                          {'source': 'b', 'target': 'c'}])
        >>> summary['node_count'], summary['edge_count']
        (3, 2)
    """
    adjacency = build_adjacency(entities, links)
    node_count = len(adjacency)
    edge_count = sum(len(neighbours) for neighbours in adjacency.values()) // 2
    components = connected_components(adjacency)
    communities = label_propagation_communities(adjacency)
    bridge_edges = bridges(adjacency)
    isolated = sum(1 for neighbours in adjacency.values() if not neighbours)
    density = (2.0 * edge_count / (node_count * (node_count - 1))
               if node_count > 1 else 0.0)
    return {
        'node_count': node_count,
        'edge_count': edge_count,
        'density': round(density, 6),
        'avg_degree': round(2.0 * edge_count / node_count, 4) if node_count else 0.0,
        'component_count': len(components),
        'largest_component_size': len(components[0]) if components else 0,
        'community_count': len(communities),
        'top_entities': top_entities(adjacency, 'degree', 5),
        'bridge_count': len(bridge_edges),
        'bridges': [{'source': u, 'target': v} for u, v in bridge_edges],
        'isolated_nodes': isolated,
    }


# ---------------------------------------------------------------------------
# Shared coercion helpers
# ---------------------------------------------------------------------------

def _as_float(value: Any) -> Optional[float]:
    """Coerce one item to a finite float, or None when impossible."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _as_int(value: Any, default: int) -> int:
    """Best-effort integer coercion with a fallback (never raises)."""
    number = _as_float(value)
    return default if number is None else int(number)
