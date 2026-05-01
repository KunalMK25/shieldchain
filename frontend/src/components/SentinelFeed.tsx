import { useEffect, useState, useRef } from 'react';
import { SentinelFeedEntry } from '../types';
import { API_URL } from '../config';

interface SentinelFeedProps {
  contractHash: string;
}

interface Summary {
  total: number;
  flagged: number;
  suspicious: number;
  clean: number;
}

export default function SentinelFeed({ contractHash }: SentinelFeedProps) {
  const [entries, setEntries] = useState<SentinelFeedEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const [summary, setSummary] = useState<Summary>({
    total: 0,
    flagged: 0,
    suspicious: 0,
    clean: 0,
  });
  const terminalRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Auto-scroll to latest entry
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [entries]);

  // Update summary when entries change
  useEffect(() => {
    const newSummary = entries.reduce(
      (acc, entry) => {
        acc.total += 1;
        if (entry.status === 'FLAGGED') acc.flagged += 1;
        else if (entry.status === 'SUSPICIOUS') acc.suspicious += 1;
        else acc.clean += 1;
        return acc;
      },
      { total: 0, flagged: 0, suspicious: 0, clean: 0 }
    );
    setSummary(newSummary);
  }, [entries]);

  // Connect to SSE endpoint
  useEffect(() => {
    if (!contractHash) {
      setConnected(false);
      setEntries([]);
      return;
    }

    const es = new EventSource(`${API_URL}/sentinel/stream/${contractHash}`);
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnected(true);
    };

    es.onmessage = (event) => {
      try {
        const entry: SentinelFeedEntry = JSON.parse(event.data);
        setEntries((prev) => [...prev, entry]);
      } catch (error) {
        console.error('Failed to parse SSE entry:', error);
      }
    };

    es.onerror = (error) => {
      console.error('SSE connection error:', error);
      setConnected(false);
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
    };
  }, [contractHash]);

  // Placeholder when no contract selected
  if (!contractHash) {
    return (
      <div className="bg-navy/50 border border-teal/20 rounded-lg p-8 text-center">
        <p className="text-gray-400 text-sm">
          No contract selected for monitoring.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-navy/50 border border-teal/20 rounded-lg overflow-hidden">
      {/* Header with status badge and summary */}
      <div className="border-b border-teal/20 p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-lg font-semibold text-white">
            Live Sentinel Feed
          </h3>
          {connected ? (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-teal rounded-full animate-pulse" />
              <span className="text-teal text-sm font-medium">LIVE</span>
            </div>
          ) : (
            <span className="text-gray-500 text-sm font-medium">
              Disconnected
            </span>
          )}
        </div>

        {/* Summary bar */}
        <div className="flex items-center gap-6 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Total Txs:</span>
            <span className="text-white font-medium">{summary.total}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Flagged:</span>
            <span className="text-critical font-medium">{summary.flagged}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Suspicious:</span>
            <span className="text-amber-500 font-medium">
              {summary.suspicious}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Clean:</span>
            <span className="text-safe font-medium">{summary.clean}</span>
          </div>
        </div>
      </div>

      {/* Terminal-style scrolling log */}
      <div
        ref={terminalRef}
        className="h-96 overflow-y-auto p-4 space-y-2 font-mono text-sm bg-black/20"
      >
        {entries.length === 0 ? (
          <p className="text-gray-500 text-center py-8">
            Waiting for transactions...
          </p>
        ) : (
          entries.map((entry, index) => (
            <LogEntry key={index} entry={entry} />
          ))
        )}
      </div>
    </div>
  );
}

interface LogEntryProps {
  entry: SentinelFeedEntry;
}

function LogEntry({ entry }: LogEntryProps) {
  const getStatusColor = () => {
    switch (entry.status) {
      case 'FLAGGED':
        return 'text-critical';
      case 'SUSPICIOUS':
        return 'text-amber-500';
      case 'NORMAL':
      default:
        return 'text-gray-400';
    }
  };

  const getStatusIcon = () => {
    switch (entry.status) {
      case 'FLAGGED':
        return (
          <span className="flex items-center gap-1">
            🚨
            <span className="w-1.5 h-1.5 bg-critical rounded-full animate-pulse" />
          </span>
        );
      case 'SUSPICIOUS':
        return '⚠';
      case 'NORMAL':
      default:
        return '✓';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString('en-US', { hour12: false });
    } catch {
      return timestamp;
    }
  };

  const formatParams = (params: Record<string, unknown>) => {
    return JSON.stringify(params, null, 0);
  };

  return (
    <div className={`flex items-start gap-3 ${getStatusColor()}`}>
      <span className="flex-shrink-0 mt-0.5">{getStatusIcon()}</span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-gray-500">[{formatTimestamp(entry.timestamp)}]</span>
          <span className="font-semibold">{entry.function}</span>
          <span className="text-gray-600 truncate">
            {formatParams(entry.params)}
          </span>
        </div>
        {entry.reason && (
          <div className="mt-1 text-xs opacity-80">
            → {entry.reason}
          </div>
        )}
      </div>
    </div>
  );
}
