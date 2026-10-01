"""
Chart and Visualization Generator
Creates visual representations of OSINT data
"""

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any, List, Optional
from pathlib import Path
import json


class ChartGenerator:
    """Generate charts and visualizations for OSINT data"""

    def __init__(self, output_dir: str = "reports/charts"):
        self.output_dir = Path(output_dir)
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
        """
        fig, ax = plt.subplots(figsize=(10, 8))
        
        labels = list(data.keys())
        values = list(data.values())
        colors = list(self.colors.values())[:len(labels)]
        
        wedges, texts, autotexts = ax.pie(
            values, labels=labels, colors=colors,
            autopct='%1.1f%%', startangle=90,
            textprops={'color': 'white', 'fontsize': 12}
        )
        
        ax.set_title(title, color='white', fontsize=16, fontweight='bold')
        
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight', 
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()
        
        return str(output_path)

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
        """
        fig, ax = plt.subplots(figsize=(12, 8))
        
        labels = list(data.keys())
        values = list(data.values())
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
        
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight',
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()
        
        return str(output_path)

    def create_threat_gauge(self, score: int, filename: str = "threat_gauge.png") -> str:
        """
        Create a threat level gauge chart
        
        Args:
            score: Threat score (0-100)
            filename: Output filename
            
        Returns:
            Path to saved chart
        """
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
        
        for start, end, color, label in zones:
            mask = (theta >= np.pi * (1 - end/100)) & (theta <= np.pi * (1 - start/100))
            ax.fill_between(theta[mask], 0, r[mask], color=color, alpha=0.3)
        
        # Needle
        needle_angle = np.pi * (1 - score/100)
        ax.annotate('', xy=(needle_angle, 0.9), xytext=(needle_angle, 0),
                   arrowprops=dict(arrowstyle='->', color='white', lw=3))
        
        # Score text
        ax.text(np.pi/2, 0.3, f'{score}', ha='center', va='center',
               fontsize=48, fontweight='bold', color='white')
        ax.text(np.pi/2, 0.1, 'Threat Score', ha='center', va='center',
               fontsize=14, color='white')
        
        ax.set_ylim(0, 1)
        ax.set_xlim(0, np.pi)
        ax.axis('off')
        ax.set_facecolor('#1a1a2e')
        fig.patch.set_facecolor('#1a1a2e')
        
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight',
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()
        
        return str(output_path)

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
        """
        fig, ax = plt.subplots(figsize=(14, 8))
        
        dates = [event['date'] for event in events]
        descriptions = [event['description'] for event in events]
        y_pos = range(len(events))
        
        ax.scatter(dates, y_pos, s=200, c=self.colors['primary'], zorder=3)
        ax.plot(dates, y_pos, color=self.colors['primary'], alpha=0.5, zorder=2)
        
        for i, (date, desc) in enumerate(zip(dates, descriptions)):
            ax.annotate(desc, (date, i), textcoords="offset points",
                       xytext=(0, 15), ha='center', color='white',
                       fontsize=10, wrap=True)
        
        ax.set_yticks(y_pos)
        ax.set_yticklabels([f'Event {i+1}' for i in range(len(events))],
                          color='white')
        ax.set_xlabel('Date', color='white', fontsize=12)
        ax.set_title(title, color='white', fontsize=16, fontweight='bold')
        ax.tick_params(colors='white')
        ax.grid(True, alpha=0.3, color='gray')
        
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight',
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()
        
        return str(output_path)

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
        
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight',
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()
        
        return str(output_path)

    def create_statistics_dashboard(self, stats: Dict[str, Any], 
                                   filename: str = "dashboard.png") -> str:
        """
        Create a statistics dashboard
        
        Args:
            stats: Statistics data
            filename: Output filename
            
        Returns:
            Path to saved chart
        """
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
        success_rate = stats.get('success_rate', 0)
        ax2.pie([success_rate, 100-success_rate],
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
        by_type = stats.get('queries_by_type', {})
        if by_type:
            labels = list(by_type.keys())
            values = list(by_type.values())
            colors = list(self.colors.values())[:len(labels)]
            ax4.bar(labels, values, color=colors)
            ax4.set_title('Queries by Type', color='white', fontsize=14)
            ax4.tick_params(colors='white')
            ax4.set_facecolor('#16213e')
        
        fig.suptitle('ObscuraLens Statistics Dashboard', 
                    color='white', fontsize=20, fontweight='bold')
        
        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight',
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()
        
        return str(output_path)
