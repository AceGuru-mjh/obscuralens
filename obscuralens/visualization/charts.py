"""
Chart and Visualization Generator
Creates visual representations of OSINT data
"""

import matplotlib

matplotlib.use('Agg')  # Non-interactive backend
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib.pyplot as plt
import numpy as np

from ..config import config

# ---------------------------------------------------------------------------
# Input coercion helpers
# ---------------------------------------------------------------------------
# Charts are rendered from whatever a tracker, a stored lookup, a plugin or an
# SDK caller happened to produce, so the numbers arriving here are not
# guaranteed to be numbers at all.  matplotlib is strict about wedge geometry
# and - since 3.11 - raises ``ValueError`` for an all-zero pie instead of
# drawing an empty axes, so every plottable value is normalised first and the
# "nothing to draw" case renders an explicit placeholder rather than raising.

_NO_DATA_MESSAGE = 'No data to plot'


def _finite(value: Any) -> Optional[float]:
    """``value`` as a finite float, or ``None`` when it is not one."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if np.isfinite(number) else None


def _clamp_percent(value: Any, default: float = 0.0) -> float:
    """Coerce *value* into a finite percentage in ``[0, 100]``."""
    number = _finite(value)
    if number is None:
        return default
    return max(0.0, min(100.0, number))


def _finite_or_zero(value: Any) -> float:
    """``value`` as a finite float, falling back to ``0.0``.

    Unlike :func:`_plottable` this keeps the entry (a bar of height zero is
    meaningful; a missing wedge is not), so it is the right coercion for bar
    charts and gauges where position - not share of a whole - is encoded.
    """
    number = _finite(value)
    return 0.0 if number is None else number


def _plottable(data: Dict[Any, Any]) -> tuple:
    """
    Split *data* into ``(labels, values)`` keeping only drawable slices.

    A slice is drawable when its key is non-empty and its value coerces to a
    finite, non-negative number.  Dropping unusable slices (instead of passing
    them to matplotlib) keeps one bad field from discarding a whole chart.
    """
    labels: List[str] = []
    values: List[float] = []
    for key, raw in (data or {}).items():
        number = _finite(raw)
        if number is None or number < 0:
            continue
        labels.append(str(key))
        values.append(number)
    return labels, values


class ChartGenerator:
    """Generate charts and visualizations for OSINT data"""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir or config.app_config.chart_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set style
        plt.style.use('dark_background')
        self.colors = {
            'primary': '#00ff88',
            'secondary': '#ff6b6b',
            'accent': '#4ecdc4',
            'warning': '#ffe66d',
            'danger': '#ff4757',
            'info': '#70a1ff'
        }

    def _save(self, fig: Any, filename: str) -> str:
        """
        Write *fig* to ``output_dir/filename`` and always release it.

        The close is in a ``finally`` because a figure that survives a failed
        save stays registered with pyplot for the life of the process - and at
        300 dpi these are tens of megabytes each, which a long-running web or
        daemon process would accumulate one bad render at a time.
        """
        output_path = self.output_dir / filename
        try:
            fig.savefig(output_path, dpi=300, bbox_inches='tight',
                        facecolor='#1a1a2e', edgecolor='none')
        finally:
            plt.close(fig)
        return str(output_path)

    def _no_data_figure(self, title: str, message: str = _NO_DATA_MESSAGE) -> Any:
        """
        A styled placeholder figure for the "nothing to draw" case.

        Returning a real figure (rather than raising or writing a zero-byte
        file) keeps every caller's contract intact: a chart path that exists,
        opens and says why it is empty.
        """
        fig, ax = plt.subplots(figsize=(10, 8))
        ax.set_facecolor('#1a1a2e')
        fig.patch.set_facecolor('#1a1a2e')
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_color('#2a2a4a')
        ax.text(0.5, 0.5, message, ha='center', va='center',
                fontsize=16, color='#8892b0')
        ax.set_title(title, color='white', fontsize=16, fontweight='bold')
        return fig

    def create_pie_chart(self, data: Dict[str, int], title: str,
                        filename: str) -> str:
        """
        Create a pie chart

        Args:
            data: Dictionary with labels and values
            title: Chart title
            filename: Output filename

        Returns:
            Path to saved chart

        Notes:
            Empty, all-zero, negative and non-numeric input renders the
            ``No data to plot`` placeholder instead of raising: matplotlib
            rejects an all-zero or negative wedge set outright (``ValueError``
            since 3.11), and a report is more useful with an explained gap
            than with a traceback.
        """
        labels, values = _plottable(data)
        if not values or sum(values) <= 0:
            # Nothing has a share of the whole, so there is no pie to draw.
            return self._save(self._no_data_figure(title), filename)

        fig, ax = plt.subplots(figsize=(10, 8))

        colors = list(self.colors.values())[:len(labels)]

        wedges, texts, autotexts = ax.pie(
            values, labels=labels, colors=colors,
            autopct='%1.1f%%', startangle=90,
            textprops={'color': 'white', 'fontsize': 12}
        )

        ax.set_title(title, color='white', fontsize=16, fontweight='bold')

        return self._save(fig, filename)

    def create_bar_chart(self, data: Dict[str, int], title: str,
                        xlabel: str, ylabel: str, filename: str,
                        horizontal: bool = False) -> str:
        """
        Create a bar chart

        Args:
            data: Dictionary with labels and values
            title: Chart title
            xlabel: X-axis label
            ylabel: Y-axis label
            filename: Output filename
            horizontal: Create horizontal bar chart

        Returns:
            Path to saved chart

        Notes:
            Bars may legitimately be negative, so unlike the pie chart this
            only requires values to be finite numbers; anything that does not
            coerce (``None``, ``''``, a stray string) is drawn as zero rather
            than aborting the whole chart.
        """
        fig, ax = plt.subplots(figsize=(12, 8))

        labels = [str(key) for key in (data or {})]
        values = [_finite_or_zero(raw) for raw in (data or {}).values()]
        colors = list(self.colors.values())[:len(labels)]

        if horizontal:
            bars = ax.barh(labels, values, color=colors)
            ax.set_xlabel(ylabel, color='white', fontsize=12)
            ax.set_ylabel(xlabel, color='white', fontsize=12)
        else:
            bars = ax.bar(labels, values, color=colors)
            ax.set_xlabel(xlabel, color='white', fontsize=12)
            ax.set_ylabel(ylabel, color='white', fontsize=12)

        ax.set_title(title, color='white', fontsize=16, fontweight='bold')
        ax.tick_params(colors='white')

        # Add value labels on bars
        for bar in bars:
            if horizontal:
                width = bar.get_width()
                ax.text(width, bar.get_y() + bar.get_height()/2,
                       f' {int(width)}', ha='left', va='center',
                       color='white', fontsize=10)
            else:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, height,
                       f'{int(height)}', ha='center', va='bottom',
                       color='white', fontsize=10)

        return self._save(fig, filename)

    def create_threat_gauge(self, score: int, filename: str = "threat_gauge.png") -> str:
        """
        Create a threat level gauge chart

        Args:
            score: Threat score (0-100)
            filename: Output filename

        Returns:
            Path to saved chart

        Notes:
            *score* is coerced into ``[0, 100]`` (non-numeric input becomes
            ``0``).  The needle angle is derived from it, so an out-of-range or
            non-numeric score used to raise instead of drawing a gauge.
        """
        value = _clamp_percent(score)
        fig, ax = plt.subplots(figsize=(8, 6))

        # Create gauge
        theta = np.linspace(0, np.pi, 100)
        r = np.ones_like(theta)

        # Color zones
        zones = [
            (0, 30, '#00ff88', 'Safe'),
            (30, 70, '#ffe66d', 'Suspicious'),
            (70, 100, '#ff4757', 'Dangerous')
        ]

        for start, end, color, _label in zones:
            mask = (theta >= np.pi * (1 - end/100)) & (theta <= np.pi * (1 - start/100))
            ax.fill_between(theta[mask], 0, r[mask], color=color, alpha=0.3)

        # Needle
        needle_angle = np.pi * (1 - value/100)
        ax.annotate('', xy=(needle_angle, 0.9), xytext=(needle_angle, 0),
                   arrowprops={'arrowstyle': '->', 'color': 'white', 'lw': 3})

        # Score text
        label = f'{int(value)}' if float(value).is_integer() else f'{value:g}'
        ax.text(np.pi/2, 0.3, label, ha='center', va='center',
               fontsize=48, fontweight='bold', color='white')
        ax.text(np.pi/2, 0.1, 'Threat Score', ha='center', va='center',
               fontsize=14, color='white')

        ax.set_ylim(0, 1)
        ax.set_xlim(0, np.pi)
        ax.axis('off')
        ax.set_facecolor('#1a1a2e')
        fig.patch.set_facecolor('#1a1a2e')

        return self._save(fig, filename)

    def create_timeline_chart(self, events: List[Dict[str, Any]],
                             title: str, filename: str) -> str:
        """
        Create a timeline chart

        Args:
            events: List of events with 'date' and 'description' keys
            title: Chart title
            filename: Output filename

        Returns:
            Path to saved chart

        Notes:
            Events missing a ``date`` are skipped rather than raising a
            ``KeyError`` (``description`` falls back to an empty label), and an
            event-less timeline renders the ``No data to plot`` placeholder.
        """
        rows = [(event.get('date'), event.get('description', ''))
                for event in (events or []) if isinstance(event, dict)]
        rows = [(date, desc) for date, desc in rows if date]
        if not rows:
            return self._save(self._no_data_figure(title), filename)

        fig, ax = plt.subplots(figsize=(14, 8))

        dates = [date for date, _ in rows]
        descriptions = [str(desc) for _, desc in rows]
        y_pos = range(len(rows))

        ax.scatter(dates, y_pos, s=200, c=self.colors['primary'], zorder=3)
        ax.plot(dates, y_pos, color=self.colors['primary'], alpha=0.5, zorder=2)

        for i, (date, desc) in enumerate(zip(dates, descriptions)):
            ax.annotate(desc, (date, i), textcoords="offset points",
                       xytext=(0, 15), ha='center', color='white',
                       fontsize=10, wrap=True)

        ax.set_yticks(y_pos)
        ax.set_yticklabels([f'Event {i+1}' for i in range(len(rows))],
                          color='white')
        ax.set_xlabel('Date', color='white', fontsize=12)
        ax.set_title(title, color='white', fontsize=16, fontweight='bold')
        ax.tick_params(colors='white')
        ax.grid(True, alpha=0.3, color='gray')

        return self._save(fig, filename)

# ------------------------------------------------------------------
    # v4.0 adapters for correlation payloads
    # ------------------------------------------------------------------

    def create_risk_gauge(self, risk: Dict[str, Any],
                          filename: str = "risk_gauge.png") -> str:
        """
        Render the correlation package's heuristic risk block as a gauge.

        Args:
            risk: {'score': 0-100, 'verdict': str, ...} from correlation.score
            filename: Output filename

        Returns:
            Path to the saved chart ('' when the risk block is unusable)
        """
        try:
            score = int(risk.get('score') or 0)
        except (TypeError, ValueError):
            return ''
        verdict = str(risk.get('verdict') or '')
        path = self.create_threat_gauge(score, filename=filename)
        if verdict:
            print(f"Risk verdict: {verdict}")
        return path

    def create_correlation_timeline(self, timeline: Dict[str, Any],
                                    title: str = 'Investigation Timeline',
                                    filename: str = 'timeline.png') -> str:
        """
        Render the correlation package's timeline payload as a chart.

        Args:
            timeline: {'events': [{'date', 'label', 'kind', ...}]} from
                correlation.build_timeline
            title: Chart title
            filename: Output filename

        Returns:
            Path to the saved chart ('' when the timeline has no events)
        """
        events = [
            {'date': event.get('date'),
             'description': f"{event.get('kind', '?')}: {event.get('label', '')}"}
            for event in (timeline or {}).get('events', [])
            if event.get('date')
        ]
        if not events:
            return ''
        return self.create_timeline_chart(events, title, filename)

    def create_word_cloud(self, text_data: str, title: str,
                         filename: str) -> str:

        """
        Create a word cloud

        Args:
            text_data: Text data for word cloud
            title: Chart title
            filename: Output filename

        Returns:
            Path to saved chart
        """
        try:
            from wordcloud import WordCloud
        except ImportError:
            return "WordCloud library not installed"

        wordcloud = WordCloud(
            width=1200, height=800,
            background_color='#1a1a2e',
            colormap='viridis',
            max_words=200
        ).generate(text_data)

        fig, ax = plt.subplots(figsize=(12, 8))
        ax.imshow(wordcloud, interpolation='bilinear')
        ax.axis('off')
        ax.set_title(title, color='white', fontsize=16, fontweight='bold')
        fig.patch.set_facecolor('#1a1a2e')

        return self._save(fig, filename)

    def create_statistics_dashboard(self, stats: Dict[str, Any],
                                   filename: str = "dashboard.png") -> str:
        """
        Create a statistics dashboard

        Args:
            stats: Statistics data
            filename: Output filename

        Returns:
            Path to saved chart

        Notes:
            Every figure in the dashboard is derived from stored statistics, so
            each value is coerced before it reaches matplotlib: ``stats`` may
            be ``None``, ``success_rate`` is clamped into ``[0, 100]`` (an
            out-of-range rate produced a negative wedge, which matplotlib
            rejects) and ``queries_by_type`` values fall back to zero.
        """
        stats = stats if isinstance(stats, dict) else {}
        fig = plt.figure(figsize=(16, 10))
        fig.patch.set_facecolor('#1a1a2e')

        # Create grid
        gs = fig.add_gridspec(2, 3, hspace=0.3, wspace=0.3)

        # Total queries
        ax1 = fig.add_subplot(gs[0, 0])
        ax1.text(0.5, 0.5, str(stats.get('total_queries', 0)),
                ha='center', va='center', fontsize=48, fontweight='bold',
                color=self.colors['primary'])
        ax1.text(0.5, 0.2, 'Total Queries', ha='center', va='center',
                fontsize=14, color='white')
        ax1.set_facecolor('#16213e')
        ax1.axis('off')

        # Success rate
        ax2 = fig.add_subplot(gs[0, 1])
        success_rate = _clamp_percent(stats.get('success_rate', 0))
        ax2.pie([success_rate, 100 - success_rate],
               colors=[self.colors['primary'], self.colors['secondary']],
               autopct='%1.1f%%', startangle=90)
        ax2.set_title('Success Rate', color='white', fontsize=14)
        ax2.set_facecolor('#16213e')

        # Recent queries
        ax3 = fig.add_subplot(gs[0, 2])
        ax3.text(0.5, 0.5, str(stats.get('recent_queries_7d', 0)),
                ha='center', va='center', fontsize=48, fontweight='bold',
                color=self.colors['accent'])
        ax3.text(0.5, 0.2, 'Recent (7 days)', ha='center', va='center',
                fontsize=14, color='white')
        ax3.set_facecolor('#16213e')
        ax3.axis('off')

        # Queries by type
        ax4 = fig.add_subplot(gs[1, :])
        by_type = stats.get('queries_by_type')
        by_type = by_type if isinstance(by_type, dict) else {}
        if by_type:
            labels = [str(key) for key in by_type]
            values = [_finite_or_zero(raw) for raw in by_type.values()]
            colors = list(self.colors.values())[:len(labels)]
            ax4.bar(labels, values, color=colors)
            ax4.set_title('Queries by Type', color='white', fontsize=14)
            ax4.tick_params(colors='white')
            ax4.set_facecolor('#16213e')

        fig.suptitle('ObscuraLens Statistics Dashboard',
                    color='white', fontsize=20, fontweight='bold')

        return self._save(fig, filename)
