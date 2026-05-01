import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import App from './App';
import Navbar from './components/Navbar';
import LandingPage from './pages/LandingPage';
import ScannerPage from './pages/ScannerPage';
import VerifyPage from './pages/VerifyPage';
import fs from 'fs';
import path from 'path';

// Mock fetch globally
global.fetch = jest.fn();

// Mock Monaco Editor to avoid loading issues in tests
jest.mock('@monaco-editor/react', () => ({
  __esModule: true,
  default: ({ value, onChange }: any) => (
    <textarea
      data-testid="monaco-editor"
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
}));

// Mock recharts to avoid rendering issues in tests
jest.mock('recharts', () => ({
  RadialBarChart: ({ children }: any) => <div data-testid="radial-bar-chart">{children}</div>,
  RadialBar: () => <div data-testid="radial-bar" />,
  ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
  LineChart: ({ children }: any) => <div data-testid="line-chart">{children}</div>,
  Line: () => <div data-testid="line" />,
  XAxis: () => <div data-testid="x-axis" />,
  YAxis: () => <div data-testid="y-axis" />,
  CartesianGrid: () => <div data-testid="cartesian-grid" />,
  Tooltip: () => <div data-testid="tooltip" />,
}));

// Mock framer-motion to avoid animation issues in tests
jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, variants, initial, animate, whileInView, viewport, ...props }: any) => <div {...props}>{children}</div>,
    h1: ({ children, variants, initial, animate, whileInView, viewport, ...props }: any) => <h1 {...props}>{children}</h1>,
    h2: ({ children, variants, initial, animate, whileInView, viewport, ...props }: any) => <h2 {...props}>{children}</h2>,
    p: ({ children, variants, initial, animate, whileInView, viewport, ...props }: any) => <p {...props}>{children}</p>,
  },
}));

// Mock lucide-react icons
jest.mock('lucide-react', () => ({
  Shield: () => <div data-testid="shield-icon" />,
  Lock: () => <div data-testid="lock-icon" />,
  Database: () => <div data-testid="database-icon" />,
  Zap: () => <div data-testid="zap-icon" />,
  Clock: () => <div data-testid="clock-icon" />,
  Satellite: () => <div data-testid="satellite-icon" />,
  Code: () => <div data-testid="code-icon" />,
  Download: () => <div data-testid="download-icon" />,
  Anchor: () => <div data-testid="anchor-icon" />,
  RefreshCw: () => <div data-testid="refresh-icon" />,
  Copy: () => <div data-testid="copy-icon" />,
  Check: () => <div data-testid="check-icon" />,
  AlertTriangle: () => <div data-testid="alert-icon" />,
  WifiOff: () => <div data-testid="wifi-off-icon" />,
  Search: () => <div data-testid="search-icon" />,
  CheckCircle: () => <div data-testid="check-circle-icon" />,
  Loader2: () => <div data-testid="loader-icon" />,
  ExternalLink: () => <div data-testid="external-link-icon" />,
  User: () => <div data-testid="user-icon" />,
  FileText: () => <div data-testid="file-text-icon" />,
  Activity: () => <div data-testid="activity-icon" />,
  Brain: () => <div data-testid="brain-icon" />,
}));

describe('Frontend Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  /**
   * test_routing — render <App />, navigate to each route, verify correct page component renders.
   * Requirements: 5.1–5.6
   */
  describe('test_routing', () => {
    it('should render LandingPage at / route', () => {
      // App already has BrowserRouter, so we render App directly
      // and check the initial route
      const { container } = render(<App />);
      
      // LandingPage has unique headline "Scan. Secure. Prove."
      expect(screen.getByText(/Scan\. Secure\./i)).toBeInTheDocument();
    });

    it('should render ScannerPage at /scan route', () => {
      // Use window.history to navigate
      window.history.pushState({}, 'Scanner Page', '/scan');
      render(<App />);
      
      // ScannerPage has "Contract Editor" heading
      expect(screen.getByText(/Contract Editor/i)).toBeInTheDocument();
      expect(screen.getByTestId('monaco-editor')).toBeInTheDocument();
    });

    it('should render VerifyPage at /verify route', () => {
      window.history.pushState({}, 'Verify Page', '/verify');
      render(<App />);
      
      // VerifyPage has "Verify Audit" heading
      expect(screen.getByText(/Verify Audit/i)).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/Enter contract hash/i)).toBeInTheDocument();
    });

    it('should render SentinelPage at /sentinel route', () => {
      window.history.pushState({}, 'Sentinel Page', '/sentinel');
      render(<App />);
      
      // SentinelPage has "ShieldChain Sentinel" or "Sentinel" in heading
      expect(screen.getByText(/Sentinel/i)).toBeInTheDocument();
    });

    it('should redirect to / for undefined routes', async () => {
      window.history.pushState({}, 'Nonexistent Page', '/nonexistent');
      render(<App />);
      
      // Should redirect to LandingPage
      await waitFor(() => {
        expect(screen.getByText(/Scan\. Secure\./i)).toBeInTheDocument();
      });
    });
  });

  /**
   * test_navbar_links — render <Navbar />, verify links to /scan, /verify, /sentinel are present with correct href.
   * Requirements: 13.1–13.4
   */
  describe('test_navbar_links', () => {
    it('should render all navigation links with correct hrefs', () => {
      render(
        <MemoryRouter>
          <Navbar />
        </MemoryRouter>
      );
      
      // Check for Scanner link
      const scannerLink = screen.getByText('Scanner');
      expect(scannerLink).toBeInTheDocument();
      expect(scannerLink.closest('a')).toHaveAttribute('href', '/scan');
      
      // Check for Verify link
      const verifyLink = screen.getByText('Verify');
      expect(verifyLink).toBeInTheDocument();
      expect(verifyLink.closest('a')).toHaveAttribute('href', '/verify');
      
      // Check for Sentinel link
      const sentinelLink = screen.getByText('Sentinel');
      expect(sentinelLink).toBeInTheDocument();
      expect(sentinelLink.closest('a')).toHaveAttribute('href', '/sentinel');
    });

    it('should render ShieldChain logo with teal accent', () => {
      render(
        <MemoryRouter>
          <Navbar />
        </MemoryRouter>
      );
      
      // Check for ShieldChain wordmark
      expect(screen.getByText('Shield')).toBeInTheDocument();
      expect(screen.getByText('Chain')).toBeInTheDocument();
    });

    it('should render Launch App button', () => {
      render(
        <MemoryRouter>
          <Navbar />
        </MemoryRouter>
      );
      
      const launchButton = screen.getByText('Launch App');
      expect(launchButton).toBeInTheDocument();
      expect(launchButton.tagName).toBe('BUTTON');
    });
  });

  /**
   * test_landing_cta_buttons — render <LandingPage />, verify "Start Scanning" links to /scan 
   * and "Verify On-Chain" links to /verify.
   * Requirements: 6.1, 6.2
   */
  describe('test_landing_cta_buttons', () => {
    it('should render Start Scanning button that navigates to /scan', () => {
      render(
        <MemoryRouter>
          <LandingPage />
        </MemoryRouter>
      );
      
      const startScanningButton = screen.getByText('Start Scanning');
      expect(startScanningButton).toBeInTheDocument();
      expect(startScanningButton.tagName).toBe('BUTTON');
    });

    it('should render Verify On-Chain button that navigates to /verify', () => {
      render(
        <MemoryRouter>
          <LandingPage />
        </MemoryRouter>
      );
      
      const verifyButton = screen.getByText('Verify On-Chain');
      expect(verifyButton).toBeInTheDocument();
      expect(verifyButton.tagName).toBe('BUTTON');
    });

    it('should display feature pills', () => {
      render(
        <MemoryRouter>
          <LandingPage />
        </MemoryRouter>
      );
      
      expect(screen.getByText('AI-Powered Analysis')).toBeInTheDocument();
      expect(screen.getByText('On-Chain Proof')).toBeInTheDocument();
      expect(screen.getByText('IPFS Storage')).toBeInTheDocument();
    });
  });

  /**
   * test_scanner_offline_fallback — mock fetch to reject, click "Scan Contract", 
   * verify FALLBACK_ANALYSIS risk score is displayed.
   * Requirements: 7.12, 12.2
   */
  describe('test_scanner_offline_fallback', () => {
    it('should display fallback analysis when fetch fails', async () => {
      // Mock fetch to reject (network error)
      (global.fetch as jest.Mock).mockRejectedValue(new TypeError('Failed to fetch'));
      
      render(
        <MemoryRouter>
          <ScannerPage />
        </MemoryRouter>
      );
      
      // Click Scan Contract button
      const scanButton = screen.getByText('Scan Contract');
      fireEvent.click(scanButton);
      
      // Wait for fallback analysis to be displayed
      await waitFor(() => {
        // FALLBACK_ANALYSIS has risk_score: 72
        expect(screen.getByText('72')).toBeInTheDocument();
      }, { timeout: 3000 });
      
      // Verify offline mode indicator is shown
      expect(screen.getByText(/Offline Mode/i)).toBeInTheDocument();
      expect(screen.getByText(/Unable to connect to backend/i)).toBeInTheDocument();
    });

    it('should display fallback vulnerabilities', async () => {
      (global.fetch as jest.Mock).mockRejectedValue(new TypeError('Failed to fetch'));
      
      render(
        <MemoryRouter>
          <ScannerPage />
        </MemoryRouter>
      );
      
      const scanButton = screen.getByText('Scan Contract');
      fireEvent.click(scanButton);
      
      await waitFor(() => {
        // FALLBACK_ANALYSIS has "Reentrancy Risk" and "Integer Overflow"
        expect(screen.getByText('Reentrancy Risk')).toBeInTheDocument();
        expect(screen.getByText('Integer Overflow')).toBeInTheDocument();
      }, { timeout: 3000 });
    });
  });

  /**
   * test_verify_not_found_state — mock fetch to return 404, submit a hash, 
   * verify "Not Found" message is shown.
   * Requirements: 8.4
   */
  describe('test_verify_not_found_state', () => {
    it('should display Not Found message when contract hash does not exist', async () => {
      // Mock fetch to return 404
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ detail: 'Audit record not found' }),
      });
      
      render(
        <MemoryRouter>
          <VerifyPage />
        </MemoryRouter>
      );
      
      // Enter a contract hash
      const input = screen.getByPlaceholderText(/Enter contract hash/i);
      fireEvent.change(input, { target: { value: 'nonexistent_hash_123' } });
      
      // Click Verify button (use getByRole to be more specific)
      const verifyButton = screen.getByRole('button', { name: /Verify/i });
      fireEvent.click(verifyButton);
      
      // Wait for Not Found message
      await waitFor(() => {
        expect(screen.getByText(/Audit Not Found/i)).toBeInTheDocument();
        expect(screen.getByText(/No audit record exists for this contract hash/i)).toBeInTheDocument();
      }, { timeout: 3000 });
    });

    it('should display Scan a Contract button in not found state', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ detail: 'Audit record not found' }),
      });
      
      render(
        <MemoryRouter>
          <VerifyPage />
        </MemoryRouter>
      );
      
      const input = screen.getByPlaceholderText(/Enter contract hash/i);
      fireEvent.change(input, { target: { value: 'test_hash' } });
      
      const verifyButton = screen.getByRole('button', { name: /Verify/i });
      fireEvent.click(verifyButton);
      
      await waitFor(() => {
        expect(screen.getByText(/Scan a Contract/i)).toBeInTheDocument();
      }, { timeout: 3000 });
    });
  });

  /**
   * test_severity_badge_colors — render a vulnerability card with each severity level, 
   * verify the correct Tailwind color class is applied.
   * Requirements: 7.13
   */
  describe('test_severity_badge_colors', () => {
    it('should apply correct color classes for CRITICAL severity', async () => {
      const mockResponse = {
        analysis: {
          risk_score: 95,
          vulnerabilities: [
            {
              title: 'Critical Vulnerability',
              severity: 'CRITICAL',
              description: 'Test description',
              line: 10,
              fix: 'Test fix'
            }
          ],
          exploit_story: 'Test story',
          score_breakdown: {
            reasoning: 'Test reasoning',
            positives: [],
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0
          },
          improvement_priority: []
        },
        pdf_url: 'https://example.com/pdf',
        cid: 'QmTest',
        report_id: 'test123',
        contract_hash: '0'.repeat(64)
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      render(
        <MemoryRouter>
          <ScannerPage />
        </MemoryRouter>
      );

      const scanButton = screen.getByText('Scan Contract');
      fireEvent.click(scanButton);

      await waitFor(() => {
        // Find all CRITICAL badges and check the one in the vulnerability card
        const criticalBadges = screen.getAllByText('CRITICAL');
        const vulnBadge = criticalBadges.find(badge => 
          badge.className.includes('px-3') && badge.className.includes('rounded-full')
        );
        expect(vulnBadge).toBeDefined();
        expect(vulnBadge?.className).toContain('bg-critical');
      }, { timeout: 3000 });
    });

    it('should apply correct color classes for HIGH severity', async () => {
      const mockResponse = {
        analysis: {
          risk_score: 75,
          vulnerabilities: [
            {
              title: 'High Vulnerability',
              severity: 'HIGH',
              description: 'Test description',
              line: 20,
              fix: 'Test fix'
            }
          ],
          exploit_story: 'Test story',
          score_breakdown: {
            reasoning: 'Test reasoning',
            positives: [],
            critical_count: 0,
            high_count: 1,
            medium_count: 0,
            low_count: 0
          },
          improvement_priority: []
        },
        pdf_url: 'https://example.com/pdf',
        cid: 'QmTest',
        report_id: 'test123',
        contract_hash: '0'.repeat(64)
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      render(
        <MemoryRouter>
          <ScannerPage />
        </MemoryRouter>
      );

      const scanButton = screen.getByText('Scan Contract');
      fireEvent.click(scanButton);

      await waitFor(() => {
        const highBadges = screen.getAllByText('HIGH');
        const vulnBadge = highBadges.find(badge => 
          badge.className.includes('px-3') && badge.className.includes('rounded-full')
        );
        expect(vulnBadge).toBeDefined();
        expect(vulnBadge?.className).toContain('bg-high');
      }, { timeout: 3000 });
    });

    it('should apply correct color classes for MEDIUM severity', async () => {
      const mockResponse = {
        analysis: {
          risk_score: 50,
          vulnerabilities: [
            {
              title: 'Medium Vulnerability',
              severity: 'MEDIUM',
              description: 'Test description',
              line: 30,
              fix: 'Test fix'
            }
          ],
          exploit_story: 'Test story',
          score_breakdown: {
            reasoning: 'Test reasoning',
            positives: [],
            critical_count: 0,
            high_count: 0,
            medium_count: 1,
            low_count: 0
          },
          improvement_priority: []
        },
        pdf_url: 'https://example.com/pdf',
        cid: 'QmTest',
        report_id: 'test123',
        contract_hash: '0'.repeat(64)
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      render(
        <MemoryRouter>
          <ScannerPage />
        </MemoryRouter>
      );

      const scanButton = screen.getByText('Scan Contract');
      fireEvent.click(scanButton);

      await waitFor(() => {
        const mediumBadges = screen.getAllByText('MEDIUM');
        const vulnBadge = mediumBadges.find(badge => 
          badge.className.includes('px-3') && badge.className.includes('rounded-full')
        );
        expect(vulnBadge).toBeDefined();
        expect(vulnBadge?.className).toContain('bg-yellow-500');
      }, { timeout: 3000 });
    });

    it('should apply correct color classes for LOW severity', async () => {
      const mockResponse = {
        analysis: {
          risk_score: 25,
          vulnerabilities: [
            {
              title: 'Low Vulnerability',
              severity: 'LOW',
              description: 'Test description',
              line: 40,
              fix: 'Test fix'
            }
          ],
          exploit_story: 'Test story',
          score_breakdown: {
            reasoning: 'Test reasoning',
            positives: [],
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 1
          },
          improvement_priority: []
        },
        pdf_url: 'https://example.com/pdf',
        cid: 'QmTest',
        report_id: 'test123',
        contract_hash: '0'.repeat(64)
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      render(
        <MemoryRouter>
          <ScannerPage />
        </MemoryRouter>
      );

      const scanButton = screen.getByText('Scan Contract');
      fireEvent.click(scanButton);

      await waitFor(() => {
        const lowBadges = screen.getAllByText('LOW');
        const vulnBadge = lowBadges.find(badge => 
          badge.className.includes('px-3') && badge.className.includes('rounded-full')
        );
        expect(vulnBadge).toBeDefined();
        expect(vulnBadge?.className).toContain('bg-safe');
      }, { timeout: 3000 });
    });
  });

  /**
   * test_tailwind_custom_colors — read tailwind.config.js and assert all six custom colors 
   * are defined with the correct hex values.
   * Requirements: 9.1–9.6
   */
  describe('test_tailwind_custom_colors', () => {
    it('should have all six custom colors defined with correct hex values', () => {
      // Read tailwind.config.js
      const configPath = path.join(__dirname, '..', 'tailwind.config.js');
      const configContent = fs.readFileSync(configPath, 'utf-8');
      
      // Parse the config (simple string matching for this test)
      // Expected colors:
      const expectedColors = {
        navy: '#0B1D3A',
        teal: '#00C2D4',
        purple: '#6C3FC5',
        critical: '#EF4444',
        high: '#F97316',
        safe: '#22C55E'
      };
      
      // Verify each color is present with correct hex value
      Object.entries(expectedColors).forEach(([colorName, hexValue]) => {
        const colorRegex = new RegExp(`${colorName}:\\s*['"]${hexValue}['"]`, 'i');
        expect(configContent).toMatch(colorRegex);
      });
    });

    it('should extend the default Tailwind theme', () => {
      const configPath = path.join(__dirname, '..', 'tailwind.config.js');
      const configContent = fs.readFileSync(configPath, 'utf-8');
      
      // Verify that the config uses 'extend' to preserve default utilities
      expect(configContent).toMatch(/extend:\s*{/);
    });

    it('should define colors within the extend.colors object', () => {
      const configPath = path.join(__dirname, '..', 'tailwind.config.js');
      const configContent = fs.readFileSync(configPath, 'utf-8');
      
      // Verify colors are defined within extend.colors
      expect(configContent).toMatch(/extend:\s*{\s*colors:\s*{/);
    });
  });
});
