import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Lock, Database, Zap, Clock, Satellite, Code } from 'lucide-react';
import Navbar from '../components/Navbar';

// Animation variants for staggered entrance
const containerVariants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.15,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0 },
};

export default function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-navy text-white">
      {/* Section 1: Navbar */}
      <Navbar />

      {/* Section 2: Hero */}
      <section className="relative pt-32 pb-20 px-4 overflow-hidden">
        {/* Animated grid background */}
        <div className="absolute inset-0 opacity-20">
          <div
            className="absolute inset-0"
            style={{
              backgroundImage: `
                linear-gradient(to right, #00C2D4 1px, transparent 1px),
                linear-gradient(to bottom, #00C2D4 1px, transparent 1px)
              `,
              backgroundSize: '40px 40px',
            }}
          />
        </div>

        <motion.div
          className="relative max-w-6xl mx-auto text-center"
          variants={containerVariants}
          initial="hidden"
          animate="visible"
        >
          {/* Headline */}
          <motion.h1
            className="text-5xl md:text-7xl font-bold mb-6"
            variants={itemVariants}
          >
            Scan. Secure. <span className="text-teal">Prove.</span>
          </motion.h1>

          {/* Subheadline */}
          <motion.p
            className="text-xl md:text-2xl text-gray-300 mb-8 max-w-3xl mx-auto"
            variants={itemVariants}
          >
            AI-powered Soroban smart contract security scanner with immutable
            on-chain audit anchoring on Stellar
          </motion.p>

          {/* Feature pills */}
          <motion.div
            className="flex flex-wrap justify-center gap-4 mb-12"
            variants={itemVariants}
          >
            <div className="bg-teal/10 border border-teal/30 rounded-full px-6 py-2 text-teal font-medium">
              AI-Powered Analysis
            </div>
            <div className="bg-purple/10 border border-purple/30 rounded-full px-6 py-2 text-purple font-medium">
              On-Chain Proof
            </div>
            <div className="bg-teal/10 border border-teal/30 rounded-full px-6 py-2 text-teal font-medium">
              IPFS Storage
            </div>
          </motion.div>

          {/* CTA buttons */}
          <motion.div
            className="flex flex-wrap justify-center gap-4"
            variants={itemVariants}
          >
            <button
              onClick={() => navigate('/scan')}
              className="bg-teal text-navy px-8 py-4 rounded-lg text-lg font-semibold hover:bg-teal/90 transition-colors shadow-lg"
            >
              Start Scanning
            </button>
            <button
              onClick={() => navigate('/verify')}
              className="bg-purple text-white px-8 py-4 rounded-lg text-lg font-semibold hover:bg-purple/90 transition-colors shadow-lg"
            >
              Verify On-Chain
            </button>
          </motion.div>
        </motion.div>
      </section>

      {/* Section 3: Features */}
      <section className="py-20 px-4 bg-navy/50">
        <motion.div
          className="max-w-6xl mx-auto"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, amount: 0.3 }}
        >
          <motion.h2
            className="text-4xl font-bold text-center mb-16"
            variants={itemVariants}
          >
            Why <span className="text-teal">ShieldChain</span>?
          </motion.h2>

          <div className="grid md:grid-cols-3 gap-8">
            {/* AI Scanner Card */}
            <motion.div
              className="bg-navy border border-teal/20 rounded-lg p-8 hover:border-teal/50 transition-colors"
              variants={itemVariants}
            >
              <div className="bg-teal/10 w-16 h-16 rounded-lg flex items-center justify-center mb-6">
                <Shield className="w-8 h-8 text-teal" />
              </div>
              <h3 className="text-2xl font-bold mb-4 text-teal">AI Scanner</h3>
              <p className="text-gray-300 leading-relaxed">
                Powered by Groq LLaMA 3.3 70B, our AI analyzes your Soroban
                contracts for vulnerabilities, generates risk scores, and
                provides actionable fix recommendations in under 60 seconds.
              </p>
            </motion.div>

            {/* On-Chain Proof Card */}
            <motion.div
              className="bg-navy border border-purple/20 rounded-lg p-8 hover:border-purple/50 transition-colors"
              variants={itemVariants}
            >
              <div className="bg-purple/10 w-16 h-16 rounded-lg flex items-center justify-center mb-6">
                <Lock className="w-8 h-8 text-purple" />
              </div>
              <h3 className="text-2xl font-bold mb-4 text-purple">
                On-Chain Proof
              </h3>
              <p className="text-gray-300 leading-relaxed">
                Every audit is anchored to Stellar Testnet via our AuditRegistry
                Soroban contract. Immutable, timestamped, and publicly
                verifiable—no central authority required.
              </p>
            </motion.div>

            {/* Sentinel Monitor Card */}
            <motion.div
              className="bg-navy border border-teal/20 rounded-lg p-8 hover:border-teal/50 transition-colors"
              variants={itemVariants}
            >
              <div className="bg-teal/10 w-16 h-16 rounded-lg flex items-center justify-center mb-6">
                <Satellite className="w-8 h-8 text-teal" />
              </div>
              <h3 className="text-2xl font-bold mb-4 text-teal">
                Sentinel Monitor
              </h3>
              <p className="text-gray-300 leading-relaxed">
                Post-deployment runtime monitoring streams Stellar Horizon
                transactions and alerts you to suspicious activity on your
                audited contracts. (Coming Soon)
              </p>
            </motion.div>
          </div>
        </motion.div>
      </section>

      {/* Section 4: Stats Bar */}
      <section className="py-16 px-4 bg-navy border-y border-teal/20">
        <motion.div
          className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, amount: 0.5 }}
        >
          {/* 100% Free */}
          <motion.div
            className="text-center"
            variants={itemVariants}
          >
            <div className="bg-teal/10 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <Zap className="w-8 h-8 text-teal" />
            </div>
            <h4 className="text-2xl font-bold text-teal mb-2">100% Free</h4>
            <p className="text-gray-400 text-sm">Open-source & accessible</p>
          </motion.div>

          {/* < 60 Second Analysis */}
          <motion.div
            className="text-center"
            variants={itemVariants}
          >
            <div className="bg-purple/10 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <Clock className="w-8 h-8 text-purple" />
            </div>
            <h4 className="text-2xl font-bold text-purple mb-2">
              &lt; 60 Second Analysis
            </h4>
            <p className="text-gray-400 text-sm">Lightning-fast results</p>
          </motion.div>

          {/* Stellar Testnet Live */}
          <motion.div
            className="text-center"
            variants={itemVariants}
          >
            <div className="bg-teal/10 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <Database className="w-8 h-8 text-teal" />
            </div>
            <h4 className="text-2xl font-bold text-teal mb-2">
              Stellar Testnet Live
            </h4>
            <p className="text-gray-400 text-sm">Real blockchain anchoring</p>
          </motion.div>

          {/* Soroban Native */}
          <motion.div
            className="text-center"
            variants={itemVariants}
          >
            <div className="bg-purple/10 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <Code className="w-8 h-8 text-purple" />
            </div>
            <h4 className="text-2xl font-bold text-purple mb-2">
              Soroban Native
            </h4>
            <p className="text-gray-400 text-sm">Built for Stellar smart contracts</p>
          </motion.div>
        </motion.div>
      </section>

      {/* Section 5: Footer */}
      <footer className="py-8 px-4 bg-navy border-t border-teal/20">
        <div className="max-w-6xl mx-auto text-center text-gray-400 text-sm">
          <p>
            &copy; {new Date().getFullYear()} ShieldChain. Built for Altaria
            v1.0 Hackathon — AI × Blockchain Track — DSCE Bangalore.
          </p>
          <p className="mt-2">
            Powered by Groq LLaMA 3.3 70B • Stellar Testnet • Pinata IPFS
          </p>
        </div>
      </footer>
    </div>
  );
}
