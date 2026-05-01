import React, { useState, useCallback } from 'react';
import { Search, CheckCircle, AlertTriangle, Loader2, ExternalLink, Clock, Shield, User, FileText, Database } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Navbar from '../components/Navbar';
import type { AuditRecord } from '../types';
import { API_URL } from '../config';

// Severity color mapping (matching ScannerPage)
const SEVERITY_COLORS = {
  CRITICAL: 'bg-critical text-white',
  HIGH: 'bg-high text-white',
  MEDIUM: 'bg-yellow-500 text-black',
  LOW: 'bg-safe text-white'
} as const;

interface VerifyState {
  query: string;
  isLoading: boolean;
  record: AuditRecord | null;
  history: AuditRecord[];
  notFound: boolean;
  error: string | null;
}

export default function VerifyPage() {
  const [state, setState] = useState<VerifyState>({
    query: '',
    isLoading: false,
    record: null,
    history: [],
    notFound: false,
    error: null
  });

  const handleVerifyWithHash = useCallback(async (hash: string) => {
    if (!hash.trim()) return;

    setState(prev => ({
      ...prev,
      isLoading: true,
      record: null,
      history: [],
      notFound: false,
      error: null
    }));

    try {
      const response = await fetch(`${API_URL}/blockchain/verify/${hash.trim()}`);

      if (response.status === 404) {
        setState(prev => ({
          ...prev,
          isLoading: false,
          notFound: true
        }));
        return;
      }

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Verification failed');
      }

      const data: AuditRecord = await response.json();
      setState(prev => ({ ...prev, isLoading: false, record: data }));

      // Fetch history after successful verification
      await fetchHistory(data.contract_hash);
    } catch (error) {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      }));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-verify if hash is provided in URL
  React.useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const hash = params.get('hash');
    if (hash) {
      setState(prev => ({ ...prev, query: hash }));
      setTimeout(() => {
        handleVerifyWithHash(hash);
      }, 100);
    }
  }, [handleVerifyWithHash]);

  const handleVerify = async () => {
    await handleVerifyWithHash(state.query);
  };

  const fetchHistory = async (contractHash: string) => {
    try {
      const response = await fetch(`${API_URL}/blockchain/history/${contractHash}`);

      if (!response.ok) {
        console.error('Failed to fetch history');
        return;
      }

      const data: AuditRecord[] = await response.json();
      setState(prev => ({ ...prev, history: data }));
    } catch (error) {
      console.error('Error fetching history:', error);
    }
  };

  const getRiskColor = (score: number): string => {
    if (score >= 85) return '#EF4444'; // red
    if (score >= 70) return '#F97316'; // orange
    if (score >= 40) return '#EAB308'; // yellow
    return '#22C55E'; // green
  };

  const getRiskLabel = (score: number): string => {
    if (score >= 85) return 'CRITICAL';
    if (score >= 70) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  };

  const formatTimestamp = (timestamp: string): string => {
    try {
      return new Date(timestamp).toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return timestamp;
    }
  };

  const formatAddress = (address: string): string => {
    if (address.length <= 16) return address;
    return `${address.slice(0, 8)}...${address.slice(-8)}`;
  };

  // Prepare chart data from history
  const chartData = state.history.map((record, index) => ({
    name: `Audit ${state.history.length - index}`,
    timestamp: formatTimestamp(record.timestamp || record.created_at || ''),
    risk_score: record.risk_score,
    fill: getRiskColor(record.risk_score)
  })).reverse(); // Reverse to show oldest first in chart

  return (
    <div className="min-h-screen bg-navy">
      <Navbar />
      
      <div className="pt-16 min-h-screen">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          {/* Header */}
          <div className="text-center mb-12">
            <div className="flex items-center justify-center gap-3 mb-4">
              <Shield className="w-10 h-10 text-teal" />
              <h1 className="text-4xl font-bold text-white">Verify Audit</h1>
            </div>
            <p className="text-gray-400 text-lg">
              Look up on-chain audit records by contract hash
            </p>
          </div>

          {/* Search Bar */}
          <div className="mb-8">
            <div className="flex gap-3">
              <div className="flex-1 relative">
                <input
                  type="text"
                  value={state.query}
                  onChange={(e) => setState(prev => ({ ...prev, query: e.target.value }))}
                  onKeyPress={(e) => e.key === 'Enter' && handleVerify()}
                  placeholder="Enter contract hash (SHA-256 hex)"
                  className="w-full bg-navy/50 border border-teal/20 rounded-lg px-4 py-3 pl-12 text-white placeholder-gray-500 focus:outline-none focus:border-teal/50 transition-colors"
                />
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
              </div>
              <button
                onClick={handleVerify}
                disabled={state.isLoading || !state.query.trim()}
                className="bg-teal text-navy px-8 py-3 rounded-lg font-semibold hover:bg-teal/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {state.isLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Verifying...
                  </>
                ) : (
                  <>
                    <Search className="w-5 h-5" />
                    Verify
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Loading State */}
          {state.isLoading && (
            <div className="text-center py-20">
              <Loader2 className="w-12 h-12 text-teal animate-spin mx-auto mb-4" />
              <p className="text-gray-400">Searching blockchain records...</p>
            </div>
          )}

          {/* Error State */}
          {state.error && (
            <div className="bg-critical/10 border border-critical/30 rounded-lg p-6 flex items-start gap-4">
              <AlertTriangle className="w-6 h-6 text-critical flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-critical font-semibold text-lg mb-1">Verification Error</h3>
                <p className="text-gray-300">{state.error}</p>
              </div>
            </div>
          )}

          {/* Not Found State */}
          {state.notFound && (
            <div className="bg-navy/50 border border-teal/20 rounded-lg p-12 text-center">
              <AlertTriangle className="w-16 h-16 text-yellow-500 mx-auto mb-4" />
              <h3 className="text-2xl font-semibold text-white mb-2">Audit Not Found</h3>
              <p className="text-gray-400 mb-6">
                No audit record exists for this contract hash. The contract may not have been audited yet.
              </p>
              <button
                onClick={() => window.location.href = '/scan'}
                className="bg-teal text-navy px-6 py-3 rounded-lg font-semibold hover:bg-teal/90 transition-colors inline-flex items-center gap-2"
              >
                <Shield className="w-5 h-5" />
                Scan a Contract
              </button>
            </div>
          )}

          {/* Verified Record */}
          {state.record && (
            <div className="space-y-8">
              {/* Verified Badge and Risk Score */}
              <div className="bg-navy/50 border border-teal/20 rounded-lg p-8">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-8 h-8 text-teal" />
                    <div>
                      <h2 className="text-2xl font-bold text-teal">✓ Verified</h2>
                      <p className="text-gray-400 text-sm">On-chain audit record found</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm text-gray-400 mb-1">Risk Score</div>
                    <div className="flex items-center gap-3">
                      <div
                        className="text-4xl font-bold"
                        style={{ color: getRiskColor(state.record.risk_score) }}
                      >
                        {state.record.risk_score}
                      </div>
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-bold ${
                          SEVERITY_COLORS[getRiskLabel(state.record.risk_score) as keyof typeof SEVERITY_COLORS]
                        }`}
                      >
                        {getRiskLabel(state.record.risk_score)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Audit Details Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div>
                      <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                        <Database className="w-4 h-4" />
                        Contract Hash
                      </div>
                      <p className="text-white font-mono text-sm break-all bg-navy/80 p-3 rounded border border-teal/10">
                        {state.record.contract_hash}
                      </p>
                    </div>

                    <div>
                      <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                        <FileText className="w-4 h-4" />
                        Report Hash
                      </div>
                      <p className="text-white font-mono text-sm break-all bg-navy/80 p-3 rounded border border-teal/10">
                        {state.record.report_hash}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                        <Clock className="w-4 h-4" />
                        Timestamp
                      </div>
                      <p className="text-white bg-navy/80 p-3 rounded border border-teal/10">
                        {formatTimestamp(state.record.timestamp || state.record.created_at || '')}
                      </p>
                    </div>

                    <div>
                      <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                        <User className="w-4 h-4" />
                        Auditor
                      </div>
                      <p className="text-white font-mono text-sm bg-navy/80 p-3 rounded border border-teal/10">
                        {formatAddress(state.record.auditor)}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Links */}
                <div className="mt-6 pt-6 border-t border-teal/20 flex flex-wrap gap-4">
                  {state.record.ipfs_cid && (
                    <a
                      href={`https://gateway.pinata.cloud/ipfs/${state.record.ipfs_cid}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-teal hover:text-teal/80 transition-colors"
                    >
                      <ExternalLink className="w-4 h-4" />
                      View PDF Report on IPFS
                    </a>
                  )}
                  {/* Only show Stellar Explorer link for real Stellar contracts (not hashes) */}
                  {state.record.contract_hash && state.record.contract_hash.startsWith('C') && state.record.contract_hash.length === 56 ? (
                    <a
                      href={`https://stellar.expert/explorer/testnet/contract/${state.record.contract_hash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-teal hover:text-teal/80 transition-colors"
                    >
                      <ExternalLink className="w-4 h-4" />
                      View on Stellar Explorer
                    </a>
                  ) : (
                    <div className="text-sm text-gray-400 italic">
                      ℹ️ Development mode - Stellar Explorer not available for local audits
                    </div>
                  )}
                  <div className="ml-auto text-sm text-gray-400">
                    Source: <span className="text-white font-medium">{state.record.source}</span>
                  </div>
                </div>
              </div>

              {/* History Timeline */}
              {state.history.length > 0 && (
                <div className="bg-navy/50 border border-teal/20 rounded-lg p-8">
                  <h3 className="text-2xl font-semibold text-white mb-6 flex items-center gap-3">
                    <Clock className="w-6 h-6 text-teal" />
                    Audit History ({state.history.length} record{state.history.length !== 1 ? 's' : ''})
                  </h3>

                  {/* Risk Score Trend Chart */}
                  {state.history.length > 1 && (
                    <div className="mb-8">
                      <h4 className="text-lg font-semibold text-white mb-4">Risk Score Trend</h4>
                      <ResponsiveContainer width="100%" height={250}>
                        <LineChart data={chartData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1B4C8C" />
                          <XAxis
                            dataKey="name"
                            stroke="#9CA3AF"
                            tick={{ fill: '#9CA3AF', fontSize: 12 }}
                          />
                          <YAxis
                            domain={[0, 100]}
                            stroke="#9CA3AF"
                            tick={{ fill: '#9CA3AF', fontSize: 12 }}
                            label={{ value: 'Risk Score', angle: -90, position: 'insideLeft', fill: '#9CA3AF' }}
                          />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#0B1D3A',
                              border: '1px solid #00C2D4',
                              borderRadius: '8px',
                              color: '#fff'
                            }}
                          />
                          <Line
                            type="monotone"
                            dataKey="risk_score"
                            stroke="#00C2D4"
                            strokeWidth={3}
                            dot={{ fill: '#00C2D4', r: 5 }}
                            activeDot={{ r: 7 }}
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  )}

                  {/* History Records List */}
                  <div className="space-y-4">
                    <h4 className="text-lg font-semibold text-white">All Audits</h4>
                    {state.history.map((record, index) => (
                      <div
                        key={index}
                        className="bg-navy/80 border border-teal/10 rounded-lg p-4 hover:border-teal/30 transition-colors"
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <span
                                className={`px-3 py-1 rounded-full text-xs font-bold ${
                                  SEVERITY_COLORS[getRiskLabel(record.risk_score) as keyof typeof SEVERITY_COLORS]
                                }`}
                              >
                                {getRiskLabel(record.risk_score)}
                              </span>
                              <span className="text-gray-400 text-sm">
                                {formatTimestamp(record.timestamp || record.created_at || '')}
                              </span>
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
                              <div>
                                <span className="text-gray-400">Risk Score:</span>
                                <span
                                  className="ml-2 font-bold"
                                  style={{ color: getRiskColor(record.risk_score) }}
                                >
                                  {record.risk_score}
                                </span>
                              </div>
                              <div>
                                <span className="text-gray-400">Auditor:</span>
                                <span className="ml-2 text-white font-mono text-xs">
                                  {formatAddress(record.auditor)}
                                </span>
                              </div>
                              {record.ipfs_cid && (
                                <div className="sm:col-span-2">
                                  <span className="text-gray-400">IPFS CID:</span>
                                  <span className="ml-2 text-white font-mono text-xs break-all">
                                    {record.ipfs_cid}
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                          <div
                            className="text-3xl font-bold flex-shrink-0"
                            style={{ color: getRiskColor(record.risk_score) }}
                          >
                            {record.risk_score}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Empty State (initial) */}
          {!state.isLoading && !state.record && !state.notFound && !state.error && (
            <div className="text-center py-20">
              <Shield className="w-16 h-16 text-teal/30 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">
                Ready to Verify
              </h3>
              <p className="text-gray-500">
                Enter a contract hash above to look up its on-chain audit record.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
