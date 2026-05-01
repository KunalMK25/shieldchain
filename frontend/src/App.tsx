import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import ScannerPage from './pages/ScannerPage';
import VerifyPage from './pages/VerifyPage';
import SentinelPage from './pages/SentinelPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/scan" element={<ScannerPage />} />
        <Route path="/verify" element={<VerifyPage />} />
        <Route path="/sentinel" element={<SentinelPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
