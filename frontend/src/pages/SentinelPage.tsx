import { Shield, Activity, Brain } from 'lucide-react';
import Navbar from '../components/Navbar';
import SentinelFeed from '../components/SentinelFeed';
import { useState, useEffect } from 'react';
import { API_URL } from '../config';

export default function SentinelPage() {
  const [demoContractHash] = useState('CSIM_DEMO_CONTRACT_001'); // Simulated contract for demo
  const [isInitializing, setIsInitializing] = useState(true);

  // Initialize demo sentinel on page load
  useEffect(() => {
    const initializeDemoSentinel = async () => {
      try {
        const response = await fetch(
          `${API_URL}/sentinel/demo/start/${demoContractHash}`,
          { method: 'POST' }
        );
        const data = await response.json();
        console.log('Demo sentinel initialized:', data);
      } catch (error) {
        console.error('Failed to initialize demo sentinel:', error);
      } finally {
        setIsInitializing(false);
      }
    };

    initializeDemoSentinel();
  }, [demoContractHash]);

  return (
    <div className="min-h-screen bg-navy text-white">
      {/* Section 1: Navbar */}
      <Navbar />

      {/* Section 2: Header */}
      <section className="pt-32 pb-12 px-4">
        <div className="max-w-6xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold mb-6">
            ShieldChain <span className="text-teal">Sentinel</span>
          </h1>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Continuous post-deployment monitoring for audited Soroban contracts.
            Sentinel streams live transactions from Stellar Horizon and alerts
            developers to suspicious activity in real-time.
          </p>
        </div>
      </section>

      {/* Section 3: How It Works */}
      <section className="py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">
            How It <span className="text-teal">Works</span>
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            {/* Boundary Check Card */}
            <div className="bg-navy border border-teal/30 rounded-lg p-6 hover:border-teal/50 transition-colors">
              <div className="flex items-center justify-center w-12 h-12 bg-teal/10 rounded-lg mb-4">
                <Shield className="w-6 h-6 text-teal" />
              </div>
              <h3 className="text-xl font-semibold mb-3 text-teal">
                Boundary Check
              </h3>
              <p className="text-gray-300">
                Validates transaction parameters against the audit baseline.
                Detects when function arguments exceed expected ranges or
                violate security constraints established during the initial scan.
              </p>
            </div>

            {/* Frequency Anomaly Card */}
            <div className="bg-navy border border-purple/30 rounded-lg p-6 hover:border-purple/50 transition-colors">
              <div className="flex items-center justify-center w-12 h-12 bg-purple/10 rounded-lg mb-4">
                <Activity className="w-6 h-6 text-purple" />
              </div>
              <h3 className="text-xl font-semibold mb-3 text-purple">
                Frequency Anomaly
              </h3>
              <p className="text-gray-300">
                Detects unusual call patterns compared to historical baseline.
                Identifies spikes in transaction volume, rapid-fire calls, or
                abnormal timing that may indicate automated attacks or exploits.
              </p>
            </div>

            {/* Intent Classification Card */}
            <div className="bg-navy border border-teal/30 rounded-lg p-6 hover:border-teal/50 transition-colors">
              <div className="flex items-center justify-center w-12 h-12 bg-teal/10 rounded-lg mb-4">
                <Brain className="w-6 h-6 text-teal" />
              </div>
              <h3 className="text-xl font-semibold mb-3 text-teal">
                Intent Classification
              </h3>
              <p className="text-gray-300">
                AI classifies transaction intent as safe, suspicious, or critical.
                Uses machine learning to analyze transaction context, caller
                reputation, and behavioral patterns for intelligent threat detection.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Section 4: Live Feed Demo */}
      <section className="py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="relative">
            {/* Live Feed Content */}
            <div className="bg-navy border border-teal/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold">
                  Live Transaction <span className="text-teal">Feed</span>
                </h2>
                <div className="text-sm text-gray-400">
                  {isInitializing ? (
                    <span className="text-gray-500">Initializing...</span>
                  ) : (
                    <>
                      Monitoring: <span className="text-teal font-mono">{demoContractHash}</span>
                    </>
                  )}
                </div>
              </div>

              {/* Use the actual SentinelFeed component */}
              {!isInitializing && <SentinelFeed contractHash={demoContractHash} />}
            </div>
          </div>
        </div>
      </section>

      {/* Footer spacing */}
      <div className="h-20" />
    </div>
  );
}
