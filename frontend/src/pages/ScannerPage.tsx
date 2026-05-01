import React, { useState, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts';
import { Shield, Download, Anchor, RefreshCw, Copy, Check, AlertTriangle, WifiOff, ExternalLink, Clock } from 'lucide-react';
import Navbar from '../components/Navbar';
import { API_URL } from '../config';
import SentinelFeed from '../components/SentinelFeed';
import type { ScanResponse, AnchorResponse, DynamicLogEntry } from '../types';

// Fallback analysis constant for offline demo mode
const FALLBACK_ANALYSIS: ScanResponse = {
  analysis: {
    risk_score: 72,
    vulnerabilities: [
      {
        title: "Reentrancy Risk",
        severity: "HIGH",
        description: "Token transfer before state update allows reentrancy.",
        line: 42,
        fix: "Update state before external calls."
      },
      {
        title: "Integer Overflow",
        severity: "MEDIUM",
        description: "Unchecked arithmetic on balance field.",
        line: 67,
        fix: "Use checked_add() for all arithmetic."
      }
    ],
    exploit_story: "An attacker deploys a malicious contract that calls back into the token contract during transfer, draining funds before the balance is updated.",
    score_breakdown: {
      reasoning: "Two vulnerabilities found: one HIGH severity reentrancy and one MEDIUM integer overflow.",
      positives: ["Authorization checks present", "No hardcoded secrets"],
      critical_count: 0,
      high_count: 1,
      medium_count: 1,
      low_count: 0
    },
    improvement_priority: [
      { order: 1, fix: "Fix reentrancy by updating state before external calls", effort: "Low", severity: "HIGH", before_code: "(bool success, ) = msg.sender.call{value: amount}(\"\");\nbalances[msg.sender] = 0;", after_code: "balances[msg.sender] = 0;\n(bool success, ) = msg.sender.call{value: amount}(\"\");", explanation: "Always update state before making external calls to prevent reentrancy." },
      { order: 2, fix: "Add checked arithmetic to prevent overflow", effort: "Low", severity: "MEDIUM", before_code: "let total = balance + amount;", after_code: "let total = balance.checked_add(amount)\n  .unwrap_or_else(|| panic!(\"overflow\"));", explanation: "Use checked_add() so the contract panics safely instead of silently overflowing." }
    ]
  },
  pdf_url: "#",
  cid: "QmOfflineFallback",
  report_id: "offline",
  contract_hash: "0".repeat(64)
};

// Severity color mapping
const SEVERITY_COLORS = {
  CRITICAL: 'bg-critical text-white',
  HIGH: 'bg-high text-white',
  MEDIUM: 'bg-yellow-500 text-black',
  LOW: 'bg-safe text-white'
} as const;

interface ScannerState {
  code: string;
  isScanning: boolean;
  scanResult: ScanResponse | null;
  scanError: string | null;
  isAnchoring: boolean;
  anchorResult: AnchorResponse | null;
  anchorError: string | null;
  expandedVuln: number | null;
  isOffline: boolean;
  activeTab: 'static' | 'dynamic';
}

export default function ScannerPage() {
  const [state, setState] = useState<ScannerState>({
    code: `#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol, String};

#[contract]
pub struct HelloContract;

#[contractimpl]
impl HelloContract {
    pub fn hello(env: Env, to: String) -> String {
        String::from_str(&env, "Hello ")
    }
}`,
    isScanning: false,
    scanResult: null,
    scanError: null,
    isAnchoring: false,
    anchorResult: null,
    anchorError: null,
    expandedVuln: null,
    isOffline: false,
    activeTab: 'static'
  });

  const [animatedScore, setAnimatedScore] = useState(0);
  const [copiedFix, setCopiedFix] = useState<number | null>(null);

  // Animate risk score gauge
  useEffect(() => {
    if (state.scanResult) {
      const targetScore = state.scanResult.analysis.risk_score;
      const duration = 1500; // 1.5 seconds
      const startTime = Date.now();

      const animate = () => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easeOutQuad = 1 - (1 - progress) * (1 - progress);
        const currentScore = Math.round(easeOutQuad * targetScore);

        setAnimatedScore(currentScore);

        if (progress < 1) {
          requestAnimationFrame(animate);
        }
      };

      requestAnimationFrame(animate);
    } else {
      setAnimatedScore(0);
    }
  }, [state.scanResult]);

  const handleScan = async () => {
    setState(prev => ({
      ...prev,
      isScanning: true,
      scanError: null,
      scanResult: null,
      anchorResult: null,
      anchorError: null,
      isOffline: false
    }));

    try {
      const response = await fetch(`${API_URL}/analyze/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contract_code: state.code,
          contract_name: 'User Contract'
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Analysis failed');
      }

      const data: ScanResponse = await response.json();
      setState(prev => ({ ...prev, isScanning: false, scanResult: data }));
    } catch (error) {
      // Network error - use fallback analysis
      if (error instanceof TypeError && error.message.includes('fetch')) {
        setState(prev => ({
          ...prev,
          isScanning: false,
          isOffline: true,
          scanResult: FALLBACK_ANALYSIS
        }));
      } else {
        setState(prev => ({
          ...prev,
          isScanning: false,
          scanError: error instanceof Error ? error.message : 'Unknown error occurred'
        }));
      }
    }
  };

  const handleAnchor = async () => {
    if (!state.scanResult) return;

    setState(prev => ({ ...prev, isAnchoring: true, anchorError: null }));

    try {
      const response = await fetch(`${API_URL}/blockchain/anchor`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contract_hash: state.scanResult.contract_hash,
          report_hash: state.scanResult.contract_hash, // Using contract_hash as report_hash for demo
          risk_score: state.scanResult.analysis.risk_score,
          ipfs_cid: state.scanResult.cid,
          dynamic_anomalies_count: state.scanResult.anomalies_found || 0,
          dynamic_risk_adjustment: state.scanResult.dynamic_risk_adjustment || 0
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Anchoring failed');
      }

      const data: AnchorResponse = await response.json();
      setState(prev => ({ ...prev, isAnchoring: false, anchorResult: data }));
    } catch (error) {
      setState(prev => ({
        ...prev,
        isAnchoring: false,
        anchorError: error instanceof Error ? error.message : 'Unknown error occurred'
      }));
    }
  };

  const handleRescan = () => {
    setState(prev => ({
      ...prev,
      scanResult: null,
      scanError: null,
      anchorResult: null,
      anchorError: null,
      isOffline: false,
      expandedVuln: null
    }));
  };

  const handleCopyFix = (fix: string, index: number) => {
    navigator.clipboard.writeText(fix);
    setCopiedFix(index);
    setTimeout(() => setCopiedFix(null), 2000);
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

  const chartData = state.scanResult ? [{
    name: 'Risk Score',
    value: animatedScore,
    fill: getRiskColor(animatedScore)
  }] : [];

  return (
    <div className="min-h-screen bg-navy">
      <Navbar />
      
      <div className="pt-16 flex flex-col lg:flex-row h-screen">
        {/* Left Panel - Monaco Editor */}
        <div className="w-full lg:w-1/2 flex flex-col border-r border-teal/20">
          <div className="bg-navy/50 border-b border-teal/20 p-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-teal" />
              <h2 className="text-lg font-semibold text-white">Contract Editor</h2>
            </div>
            <button
              onClick={handleScan}
              disabled={state.isScanning || !state.code.trim()}
              className="bg-teal text-navy px-6 py-2 rounded-md font-semibold hover:bg-teal/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {state.isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  Scan Contract
                </>
              )}
            </button>
          </div>
          
          <div className="flex-1">
            <Editor
              height="100%"
              defaultLanguage="rust"
              theme="vs-dark"
              value={state.code}
              onChange={(value) => setState(prev => ({ ...prev, code: value || '' }))}
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                automaticLayout: true
              }}
            />
          </div>
        </div>

        {/* Right Panel - Results Dashboard */}
        <div className="w-full lg:w-1/2 overflow-y-auto bg-navy">
          <div className="p-6 space-y-6">
            {state.isOffline && (
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
                <WifiOff className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-yellow-500 font-semibold">Offline Mode</h3>
                  <p className="text-gray-300 text-sm mt-1">
                    Unable to connect to backend. Showing cached analysis for demonstration.
                  </p>
                </div>
              </div>
            )}

            {state.scanError && (
              <div className="bg-critical/10 border border-critical/30 rounded-lg p-4 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-critical flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-critical font-semibold">Scan Error</h3>
                  <p className="text-gray-300 text-sm mt-1">{state.scanError}</p>
                </div>
              </div>
            )}

            {!state.scanResult && !state.isScanning && !state.scanError && (
              <div className="text-center py-20">
                <Shield className="w-16 h-16 text-teal/30 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-gray-400 mb-2">
                  Ready to Scan
                </h3>
                <p className="text-gray-500">
                  Paste your Soroban contract code and click "Scan Contract" to begin analysis.
                </p>
              </div>
            )}

            {state.scanResult && (
              <>
                {/* Tab Bar - only show when dynamic_audit_log is present */}
                {state.scanResult.dynamic_audit_log && (
                  <div className="bg-navy/50 border border-teal/20 rounded-lg overflow-hidden mb-6">
                    <div className="flex border-b border-teal/20">
                      <button
                        onClick={() => setState(prev => ({ ...prev, activeTab: 'static' }))}
                        className={`flex-1 px-6 py-3 font-semibold transition-colors ${
                          state.activeTab === 'static'
                            ? 'bg-teal/10 text-teal border-b-2 border-teal'
                            : 'text-gray-400 hover:text-white hover:bg-teal/5'
                        }`}
                      >
                        Static Analysis
                      </button>
                      <button
                        onClick={() => setState(prev => ({ ...prev, activeTab: 'dynamic' }))}
                        className={`flex-1 px-6 py-3 font-semibold transition-colors ${
                          state.activeTab === 'dynamic'
                            ? 'bg-teal/10 text-teal border-b-2 border-teal'
                            : 'text-gray-400 hover:text-white hover:bg-teal/5'
                        }`}
                      >
                        <span className="flex items-center justify-center gap-2">
                          Dynamic Analysis
                          {state.scanResult.anomalies_found != null && state.scanResult.anomalies_found > 0 && (
                            <span className="inline-flex items-center justify-center w-5 h-5 text-xs font-bold text-white bg-critical rounded-full ml-1">
                              {state.scanResult.anomalies_found}
                            </span>
                          )}
                        </span>
                      </button>
                    </div>
                  </div>
                )}

                {/* Static Analysis Tab Content */}
                {(!state.scanResult.dynamic_audit_log || state.activeTab === 'static') && (
                  <>
                {/* Risk Gauge */}
                <div className="bg-navy/50 border border-teal/20 rounded-lg p-6">
                  <h3 className="text-xl font-semibold text-white mb-4 text-center">
                    Security Risk Score
                  </h3>
                  <ResponsiveContainer width="100%" height={200}>
                    <RadialBarChart
                      cx="50%"
                      cy="50%"
                      innerRadius="60%"
                      outerRadius="90%"
                      barSize={20}
                      data={chartData}
                      startAngle={180}
                      endAngle={0}
                    >
                      <RadialBar
                        background
                        dataKey="value"
                        cornerRadius={10}
                      />
                    </RadialBarChart>
                  </ResponsiveContainer>
                  <div className="text-center mt-4">
                    <div className="text-5xl font-bold" style={{ color: getRiskColor(animatedScore) }}>
                      {animatedScore}
                    </div>
                    <div className="text-sm text-gray-400 mt-2">
                      Risk Level: <span className={`font-semibold ${SEVERITY_COLORS[getRiskLabel(animatedScore) as keyof typeof SEVERITY_COLORS]?.replace('bg-', 'text-')}`}>
                        {getRiskLabel(animatedScore)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Vulnerability Cards — Agent 1: Vulnerability Hunter */}
                {state.scanResult.analysis.vulnerabilities.length > 0 && (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <h3 className="text-xl font-semibold text-white">
                        Vulnerabilities ({state.scanResult.analysis.vulnerabilities.length})
                      </h3>
                      <span className="text-xs bg-teal/20 text-teal border border-teal/30 px-2 py-0.5 rounded-full">Agent 1 · Vulnerability Hunter</span>
                    </div>
                    {state.scanResult.analysis.vulnerabilities.map((vuln, index) => (
                      <div
                        key={index}
                        className="bg-navy/50 border border-teal/20 rounded-lg overflow-hidden"
                      >
                        <button
                          onClick={() => setState(prev => ({
                            ...prev,
                            expandedVuln: prev.expandedVuln === index ? null : index
                          }))}
                          className="w-full p-4 text-left hover:bg-teal/5 transition-colors"
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1">
                              <div className="flex items-center gap-3 mb-2">
                                <span className={`px-3 py-1 rounded-full text-xs font-bold ${SEVERITY_COLORS[vuln.severity]}`}>
                                  {vuln.severity}
                                </span>
                                <span className="text-gray-400 text-sm">Line {vuln.line}</span>
                              </div>
                              <h4 className="text-white font-semibold">{vuln.title}</h4>
                              <p className="text-gray-400 text-sm mt-1">{vuln.description}</p>
                            </div>
                            <AlertTriangle className={`w-5 h-5 flex-shrink-0 ${
                              vuln.severity === 'CRITICAL' ? 'text-critical' :
                              vuln.severity === 'HIGH' ? 'text-high' :
                              vuln.severity === 'MEDIUM' ? 'text-yellow-500' :
                              'text-safe'
                            }`} />
                          </div>
                        </button>
                        
                        {state.expandedVuln === index && (
                          <div className="border-t border-teal/20 p-4 bg-navy/80">
                            <h5 className="text-teal font-semibold mb-2">Recommended Fix:</h5>
                            <p className="text-gray-300 text-sm mb-3">{vuln.fix}</p>
                            <button
                              onClick={() => handleCopyFix(vuln.fix, index)}
                              className="bg-teal/10 hover:bg-teal/20 text-teal px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center gap-2"
                            >
                              {copiedFix === index ? (
                                <>
                                  <Check className="w-4 h-4" />
                                  Copied!
                                </>
                              ) : (
                                <>
                                  <Copy className="w-4 h-4" />
                                  Copy Fix
                                </>
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Score Breakdown */}
                {state.scanResult.analysis.score_breakdown && (
                  <div className="bg-navy/50 border border-teal/20 rounded-lg p-6">
                    <h3 className="text-xl font-semibold text-white mb-4">Score Breakdown</h3>
                    
                    <div className="space-y-4">
                      <div>
                        <h4 className="text-teal font-semibold mb-2">Reasoning:</h4>
                        <p className="text-gray-300 text-sm">
                          {state.scanResult.analysis.score_breakdown.reasoning}
                        </p>
                      </div>

                      {state.scanResult.analysis.score_breakdown.positives.length > 0 && (
                        <div>
                          <h4 className="text-safe font-semibold mb-2">Positive Findings:</h4>
                          <ul className="list-disc list-inside space-y-1">
                            {state.scanResult.analysis.score_breakdown.positives.map((positive, idx) => (
                              <li key={idx} className="text-gray-300 text-sm">{positive}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      <div>
                        <h4 className="text-white font-semibold mb-2">Severity Counts:</h4>
                        <div className="grid grid-cols-2 gap-3">
                          <div className="bg-critical/10 border border-critical/30 rounded p-3">
                            <div className="text-critical text-2xl font-bold">
                              {state.scanResult.analysis.score_breakdown.critical_count}
                            </div>
                            <div className="text-gray-400 text-sm">Critical</div>
                          </div>
                          <div className="bg-high/10 border border-high/30 rounded p-3">
                            <div className="text-high text-2xl font-bold">
                              {state.scanResult.analysis.score_breakdown.high_count}
                            </div>
                            <div className="text-gray-400 text-sm">High</div>
                          </div>
                          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-3">
                            <div className="text-yellow-500 text-2xl font-bold">
                              {state.scanResult.analysis.score_breakdown.medium_count}
                            </div>
                            <div className="text-gray-400 text-sm">Medium</div>
                          </div>
                          <div className="bg-safe/10 border border-safe/30 rounded p-3">
                            <div className="text-safe text-2xl font-bold">
                              {state.scanResult.analysis.score_breakdown.low_count}
                            </div>
                            <div className="text-gray-400 text-sm">Low</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Improvement Priority — Agent 3: Remediation Advisor */}
                {state.scanResult.analysis.improvement_priority && state.scanResult.analysis.improvement_priority.length > 0 && (
                  <div className="bg-navy/50 border border-teal/20 rounded-lg p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <h3 className="text-xl font-semibold text-white">Code Fixes</h3>
                      <span className="text-xs bg-purple/20 text-purple border border-purple/30 px-2 py-0.5 rounded-full">Agent 3 · Remediation Advisor</span>
                    </div>
                    <div className="space-y-4">
                      {state.scanResult.analysis.improvement_priority.map((item) => (
                        <div key={item.order} className="bg-navy/80 rounded-lg border border-teal/10 overflow-hidden">
                          {/* Header */}
                          <div className="flex items-start gap-4 p-4">
                            <div className="flex-shrink-0 w-8 h-8 bg-teal/20 rounded-full flex items-center justify-center">
                              <span className="text-teal font-bold text-sm">{item.order}</span>
                            </div>
                            <div className="flex-1">
                              <p className="text-white text-sm font-medium mb-1">{item.fix}</p>
                              {item.explanation && (
                                <p className="text-gray-400 text-xs mb-2">{item.explanation}</p>
                              )}
                              <div className="flex items-center gap-3 text-xs">
                                <span className="text-gray-400">
                                  Effort: <span className="text-white font-medium">{item.effort}</span>
                                </span>
                                <span className="text-gray-400">•</span>
                                <span className="text-gray-400">
                                  Severity: <span className={`font-medium ${
                                    item.severity === 'CRITICAL' ? 'text-critical' :
                                    item.severity === 'HIGH' ? 'text-high' :
                                    item.severity === 'MEDIUM' ? 'text-yellow-500' :
                                    'text-safe'
                                  }`}>{item.severity}</span>
                                </span>
                              </div>
                            </div>
                          </div>
                          {/* Before / After code */}
                          {(item.before_code || item.after_code) && (
                            <div className="grid grid-cols-2 border-t border-teal/10">
                              {item.before_code && (
                                <div className="p-3 border-r border-teal/10">
                                  <p className="text-xs text-critical font-semibold mb-1">❌ Before</p>
                                  <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap break-all">{item.before_code}</pre>
                                </div>
                              )}
                              {item.after_code && (
                                <div className="p-3">
                                  <p className="text-xs text-safe font-semibold mb-1">✅ After</p>
                                  <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap break-all">{item.after_code}</pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Exploit Narrative — Agent 2: Exploit Narrator */}
                <div className="bg-navy/50 border border-teal/20 rounded-lg p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <h3 className="text-xl font-semibold text-white">Exploit Narrative</h3>
                    <span className="text-xs bg-high/20 text-high border border-high/30 px-2 py-0.5 rounded-full">Agent 2 · Exploit Narrator</span>
                  </div>
                  <p className="text-gray-300 text-sm leading-relaxed">
                    {state.scanResult.analysis.exploit_story}
                  </p>
                </div>

                {/* Action Buttons */}
                <div className="space-y-3">
                  <a
                    href={state.scanResult.pdf_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full bg-purple hover:bg-purple/90 text-white px-6 py-3 rounded-md font-semibold transition-colors flex items-center justify-center gap-2"
                  >
                    <Download className="w-5 h-5" />
                    Download PDF Report
                  </a>

                  {!state.anchorResult && (
                    <button
                      onClick={handleAnchor}
                      disabled={state.isAnchoring}
                      className="w-full bg-teal hover:bg-teal/90 text-navy px-6 py-3 rounded-md font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                    >
                      {state.isAnchoring ? (
                        <>
                          <RefreshCw className="w-5 h-5 animate-spin" />
                          Anchoring...
                        </>
                      ) : (
                        <>
                          <Anchor className="w-5 h-5" />
                          Anchor on Stellar
                        </>
                      )}
                    </button>
                  )}

                  {state.anchorError && (
                    <div className="bg-critical/10 border border-critical/30 rounded-lg p-4">
                      <p className="text-critical text-sm">{state.anchorError}</p>
                    </div>
                  )}

                  {state.anchorResult && (
                    <div className="bg-safe/10 border border-safe/30 rounded-lg p-4">
                      <h4 className="text-safe font-semibold mb-2 flex items-center gap-2">
                        <Check className="w-5 h-5" />
                        Successfully Anchored
                      </h4>
                      <div className="space-y-2 text-sm">
                        <div>
                          <span className="text-gray-400">Transaction Hash:</span>
                          <p className="text-white font-mono text-xs break-all mt-1">
                            {state.anchorResult.tx_hash}
                          </p>
                        </div>
                        <div>
                          <span className="text-gray-400">Source:</span>
                          <span className="text-white ml-2">{state.anchorResult.source === 'stellar' ? 'Stellar Blockchain' : 'Local Store (Development)'}</span>
                        </div>
                        <div className="flex flex-col gap-2 mt-3">
                          <a
                            href={`/verify?hash=${state.scanResult?.contract_hash}`}
                            className="inline-block text-teal hover:text-teal/80 underline"
                          >
                            View Audit Record →
                          </a>
                          {state.anchorResult.source === 'stellar' && (
                            <a
                              href={state.anchorResult.explorer_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-block text-teal hover:text-teal/80 underline"
                            >
                              View on Stellar Explorer →
                            </a>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  <button
                    onClick={handleRescan}
                    className="w-full bg-navy/50 hover:bg-navy/70 border border-teal/20 text-white px-6 py-3 rounded-md font-semibold transition-colors flex items-center justify-center gap-2"
                  >
                    <RefreshCw className="w-5 h-5" />
                    Re-scan
                  </button>
                </div>
                  </>
                )}

                {/* Dynamic Analysis Tab Content */}
                {state.activeTab === 'dynamic' && (
                  <div className="space-y-6">
                    {/* Show content only if dynamic analysis was attempted */}
                    {state.scanResult.dynamic_audit_log && (
                      <>
                        {/* Error Banners */}
                        {state.scanResult.dynamic_status === 'DEPLOY_FAILED' && (
                          <div className="bg-critical/10 border border-critical/30 rounded-lg p-4 flex items-start gap-3">
                            <AlertTriangle className="w-5 h-5 text-critical flex-shrink-0 mt-0.5" />
                            <div>
                              <h3 className="text-critical font-semibold">Deployment Failed</h3>
                              <p className="text-gray-300 text-sm mt-1">
                                Unable to deploy contract to Stellar Testnet. Dynamic analysis could not be performed.
                              </p>
                            </div>
                          </div>
                        )}

                    {state.scanResult.dynamic_status === 'HORIZON_UNAVAILABLE' && (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
                        <WifiOff className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                        <div>
                          <h3 className="text-yellow-500 font-semibold">Horizon API Unavailable</h3>
                          <p className="text-gray-300 text-sm mt-1">
                            Unable to retrieve transaction logs from Stellar Horizon. Showing partial results.
                          </p>
                        </div>
                      </div>
                    )}

                    {state.scanResult.dynamic_status === 'TIMEOUT' && (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
                        <Clock className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                        <div>
                          <h3 className="text-yellow-500 font-semibold">Analysis Timeout</h3>
                          <p className="text-gray-300 text-sm mt-1">
                            Dynamic analysis exceeded the time limit. Showing partial results.
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Contract ID Card */}
                    {state.scanResult.contract_id && (
                      <div className="bg-navy/50 border border-teal/20 rounded-lg p-6">
                        <h3 className="text-xl font-semibold text-white mb-4">Deployed Contract</h3>
                        <div className="space-y-3">
                          <div>
                            <span className="text-gray-400 text-sm">Contract ID:</span>
                            <p className="text-white font-mono text-sm break-all mt-1">
                              {state.scanResult.contract_id}
                            </p>
                          </div>
                          {state.scanResult.contract_id.startsWith('CSIM') ? (
                            <div className="text-sm text-gray-400 italic">
                              ℹ️ Simulated contract (development mode)
                            </div>
                          ) : (
                            <a
                              href={`https://stellar.expert/explorer/testnet/contract/${state.scanResult.contract_id}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-2 text-teal hover:text-teal/80 text-sm font-medium"
                            >
                              View on Stellar Explorer
                              <ExternalLink className="w-4 h-4" />
                            </a>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Dynamic Risk Adjustment Card */}
                    {state.scanResult.dynamic_risk_adjustment !== undefined && (
                      <div className="bg-navy/50 border border-teal/20 rounded-lg p-6">
                        <h3 className="text-xl font-semibold text-white mb-4">Dynamic Risk Adjustment</h3>
                        <div className="flex items-center gap-4">
                          <div className={`text-4xl font-bold ${
                            state.scanResult.dynamic_risk_adjustment > 0 ? 'text-critical' : 
                            state.scanResult.dynamic_risk_adjustment < 0 ? 'text-safe' : 
                            'text-gray-400'
                          }`}>
                            {state.scanResult.dynamic_risk_adjustment > 0 ? '+' : ''}
                            {state.scanResult.dynamic_risk_adjustment}
                          </div>
                          <div className="flex-1">
                            <p className="text-gray-300 text-sm">
                              {state.scanResult.anomalies_found && state.scanResult.anomalies_found > 0
                                ? `Risk increased by ${state.scanResult.dynamic_risk_adjustment} points due to ${state.scanResult.anomalies_found} anomalous transaction${state.scanResult.anomalies_found > 1 ? 's' : ''}`
                                : 'No anomalies detected during runtime testing'}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Anomaly Count Badge */}
                    {state.scanResult.anomalies_found !== undefined && state.scanResult.anomalies_found > 0 && (
                      <div className="bg-critical/10 border border-critical/30 rounded-lg p-4 flex items-start gap-3">
                        <AlertTriangle className="w-5 h-5 text-critical flex-shrink-0 mt-0.5" />
                        <div>
                          <h3 className="text-critical font-semibold">
                            {state.scanResult.anomalies_found} Anomal{state.scanResult.anomalies_found > 1 ? 'ies' : 'y'} Detected
                          </h3>
                          <p className="text-gray-300 text-sm mt-1">
                            Runtime testing identified suspicious behavior. Review the transactions below for details.
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Fuzzing Transactions Table */}
                    {state.scanResult.dynamic_audit_log && state.scanResult.dynamic_audit_log.length > 0 && (
                      <div className="bg-navy/50 border border-teal/20 rounded-lg overflow-hidden">
                        <div className="p-6 border-b border-teal/20">
                          <h3 className="text-xl font-semibold text-white">Fuzzing Transactions</h3>
                        </div>
                        <div className="overflow-x-auto">
                          <table className="w-full">
                            <thead className="bg-navy/80">
                              <tr>
                                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                  Timestamp
                                </th>
                                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                  Function
                                </th>
                                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                  Parameters
                                </th>
                                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                  Status
                                </th>
                                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                  Reason
                                </th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-teal/10">
                              {state.scanResult.dynamic_audit_log.map((entry: DynamicLogEntry, index: number) => (
                                <tr
                                  key={index}
                                  className={`${
                                    entry.status === 'FLAGGED'
                                      ? 'bg-critical/5 hover:bg-critical/10'
                                      : entry.status === 'SUSPICIOUS'
                                      ? 'bg-yellow-500/5 hover:bg-yellow-500/10'
                                      : 'hover:bg-teal/5'
                                  } transition-colors`}
                                >
                                  <td className="px-4 py-3 text-sm text-gray-300 font-mono">
                                    {new Date(entry.timestamp).toLocaleTimeString('en-US', { 
                                      hour12: false,
                                      hour: '2-digit',
                                      minute: '2-digit',
                                      second: '2-digit'
                                    })}
                                  </td>
                                  <td className="px-4 py-3 text-sm text-white font-medium">
                                    {entry.function_called}
                                  </td>
                                  <td className="px-4 py-3 text-sm text-gray-400 font-mono max-w-xs truncate">
                                    {JSON.stringify(entry.parameters)}
                                  </td>
                                  <td className="px-4 py-3">
                                    <span
                                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                        entry.status === 'FLAGGED'
                                          ? 'bg-critical text-white'
                                          : entry.status === 'SUSPICIOUS'
                                          ? 'bg-yellow-500 text-black'
                                          : 'bg-safe text-white'
                                      }`}
                                    >
                                      {entry.status}
                                    </span>
                                  </td>
                                  <td className="px-4 py-3 text-sm text-gray-300 max-w-md">
                                    {entry.reason || (entry.error ? `Error: ${entry.error}` : entry.result || '—')}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                    </>
                    )}

                    {/* Sentinel Feed Component - Always show in Dynamic tab */}
                    <div>
                      <h3 className="text-xl font-semibold text-white mb-4">Live Monitoring</h3>
                      <SentinelFeed contractHash={state.scanResult.contract_hash} />
                    </div>

                    {/* Action Buttons for Dynamic Tab */}
                    <div className="space-y-3">
                      <a
                        href={state.scanResult.pdf_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="w-full bg-purple hover:bg-purple/90 text-white px-6 py-3 rounded-md font-semibold transition-colors flex items-center justify-center gap-2"
                      >
                        <Download className="w-5 h-5" />
                        Download PDF Report
                      </a>

                      <button
                        onClick={handleRescan}
                        className="w-full bg-navy/50 hover:bg-navy/70 border border-teal/20 text-white px-6 py-3 rounded-md font-semibold transition-colors flex items-center justify-center gap-2"
                      >
                        <RefreshCw className="w-5 h-5" />
                        Re-scan
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
