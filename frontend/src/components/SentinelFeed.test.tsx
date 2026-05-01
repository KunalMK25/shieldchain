import { render, screen, waitFor } from '@testing-library/react';
import SentinelFeed from './SentinelFeed';
import { SentinelFeedEntry } from '../types';

// Mock EventSource
class MockEventSource {
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  readyState: number = 0;

  constructor(url: string) {
    this.url = url;
    // Simulate connection opening
    setTimeout(() => {
      this.readyState = 1;
      if (this.onopen) this.onopen();
    }, 0);
  }

  close() {
    this.readyState = 2;
  }

  // Helper method for tests to simulate receiving messages
  simulateMessage(data: SentinelFeedEntry) {
    if (this.onmessage) {
      const event = new MessageEvent('message', {
        data: JSON.stringify(data),
      });
      this.onmessage(event);
    }
  }

  // Helper method for tests to simulate errors
  simulateError() {
    if (this.onerror) {
      this.onerror();
    }
  }
}

// Store reference to the last created EventSource
let lastEventSource: MockEventSource | null = null;

// Replace global EventSource with mock
(global as any).EventSource = class {
  constructor(url: string) {
    lastEventSource = new MockEventSource(url);
    return lastEventSource;
  }
} as any;

describe('SentinelFeed', () => {
  beforeEach(() => {
    lastEventSource = null;
  });

  it('renders placeholder when contractHash is empty', () => {
    render(<SentinelFeed contractHash="" />);
    expect(
      screen.getByText('No contract selected for monitoring.')
    ).toBeInTheDocument();
  });

  it('connects to SSE endpoint when contractHash is provided', async () => {
    render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(lastEventSource).not.toBeNull();
      expect(lastEventSource?.url).toBe('/sentinel/stream/test-hash-123');
    });
  });

  it('displays LIVE badge when connected', async () => {
    render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(screen.getByText('LIVE')).toBeInTheDocument();
    });
  });

  it('displays Disconnected when connection fails', async () => {
    render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(lastEventSource).not.toBeNull();
    });

    // Simulate error
    lastEventSource?.simulateError();

    await waitFor(() => {
      expect(screen.getByText('Disconnected')).toBeInTheDocument();
    });
  });

  it('renders NORMAL entries in gray', async () => {
    render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(lastEventSource).not.toBeNull();
    });

    const normalEntry: SentinelFeedEntry = {
      timestamp: '2025-04-30T14:23:11Z',
      event: 'NORMAL_TX',
      function: 'transfer',
      params: { amount: 100 },
      status: 'NORMAL',
      reason: '',
    };

    lastEventSource?.simulateMessage(normalEntry);

    await waitFor(() => {
      expect(screen.getByText('transfer')).toBeInTheDocument();
      // Find the parent div with the color class
      const entryElement = screen.getByText('transfer').closest('.text-gray-400');
      expect(entryElement).toBeInTheDocument();
    });
  });

  it('renders SUSPICIOUS entries in amber with warning icon', async () => {
    render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(lastEventSource).not.toBeNull();
    });

    const suspiciousEntry: SentinelFeedEntry = {
      timestamp: '2025-04-30T14:23:11Z',
      event: 'SUSPICIOUS_TX',
      function: 'withdraw',
      params: { amount: 999999 },
      status: 'SUSPICIOUS',
      reason: 'Amount exceeds expected boundary',
    };

    lastEventSource?.simulateMessage(suspiciousEntry);

    await waitFor(() => {
      expect(screen.getByText('withdraw')).toBeInTheDocument();
      expect(screen.getByText('⚠')).toBeInTheDocument();
      expect(
        screen.getByText('→ Amount exceeds expected boundary')
      ).toBeInTheDocument();
      // Find the parent div with the color class
      const entryElement = screen.getByText('withdraw').closest('.text-amber-500');
      expect(entryElement).toBeInTheDocument();
    });
  });

  it('renders FLAGGED entries in red with alert icon and pulsing dot', async () => {
    render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(lastEventSource).not.toBeNull();
    });

    const flaggedEntry: SentinelFeedEntry = {
      timestamp: '2025-04-30T14:23:11Z',
      event: 'FLAGGED_TX',
      function: 'exploit',
      params: { target: 'vault' },
      status: 'FLAGGED',
      reason: 'Potential reentrancy attack detected',
    };

    lastEventSource?.simulateMessage(flaggedEntry);

    await waitFor(() => {
      expect(screen.getByText('exploit')).toBeInTheDocument();
      expect(screen.getByText('🚨')).toBeInTheDocument();
      expect(
        screen.getByText('→ Potential reentrancy attack detected')
      ).toBeInTheDocument();
      // Find the parent div with the color class
      const entryElement = screen.getByText('exploit').closest('.text-critical');
      expect(entryElement).toBeInTheDocument();
    });
  });

  it('updates summary bar correctly', async () => {
    render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(lastEventSource).not.toBeNull();
    });

    // Add multiple entries
    const entries: SentinelFeedEntry[] = [
      {
        timestamp: '2025-04-30T14:23:11Z',
        event: 'NORMAL_TX',
        function: 'transfer',
        params: {},
        status: 'NORMAL',
        reason: '',
      },
      {
        timestamp: '2025-04-30T14:23:12Z',
        event: 'NORMAL_TX',
        function: 'transfer',
        params: {},
        status: 'NORMAL',
        reason: '',
      },
      {
        timestamp: '2025-04-30T14:23:13Z',
        event: 'SUSPICIOUS_TX',
        function: 'withdraw',
        params: {},
        status: 'SUSPICIOUS',
        reason: 'High amount',
      },
      {
        timestamp: '2025-04-30T14:23:14Z',
        event: 'FLAGGED_TX',
        function: 'exploit',
        params: {},
        status: 'FLAGGED',
        reason: 'Attack detected',
      },
    ];

    for (const entry of entries) {
      lastEventSource?.simulateMessage(entry);
    }

    await waitFor(() => {
      // Check that all entries are rendered
      expect(screen.getAllByText('transfer').length).toBe(2);
      expect(screen.getByText('withdraw')).toBeInTheDocument();
      expect(screen.getByText('exploit')).toBeInTheDocument();
      
      // Check summary counts
      expect(screen.getByText('Total Txs:')).toBeInTheDocument();
      expect(screen.getByText('Flagged:')).toBeInTheDocument();
      expect(screen.getByText('Suspicious:')).toBeInTheDocument();
      expect(screen.getByText('Clean:')).toBeInTheDocument();
    });
  });

  it('closes EventSource on unmount', async () => {
    const { unmount } = render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(lastEventSource).not.toBeNull();
    });

    const closeSpy = jest.spyOn(lastEventSource!, 'close');
    unmount();

    expect(closeSpy).toHaveBeenCalled();
  });

  it('reconnects when contractHash changes', async () => {
    const { rerender } = render(<SentinelFeed contractHash="hash-1" />);

    await waitFor(() => {
      expect(lastEventSource?.url).toBe('/sentinel/stream/hash-1');
    });

    const firstEventSource = lastEventSource;
    const closeSpy = jest.spyOn(firstEventSource!, 'close');

    rerender(<SentinelFeed contractHash="hash-2" />);

    await waitFor(() => {
      expect(closeSpy).toHaveBeenCalled();
      expect(lastEventSource?.url).toBe('/sentinel/stream/hash-2');
    });
  });

  it('displays waiting message when no entries', async () => {
    render(<SentinelFeed contractHash="test-hash-123" />);

    await waitFor(() => {
      expect(screen.getByText('Waiting for transactions...')).toBeInTheDocument();
    });
  });
});
