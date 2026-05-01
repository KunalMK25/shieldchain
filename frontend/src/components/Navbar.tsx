import { NavLink, useNavigate } from 'react-router-dom';

export default function Navbar() {
  const navigate = useNavigate();

  return (
    <nav className="fixed top-0 z-50 w-full bg-navy border-b border-teal/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Left: ShieldChain wordmark with teal accent on "Shield" */}
          <div className="flex-shrink-0">
            <h1 className="text-2xl font-bold">
              <span className="text-teal">Shield</span>
              <span className="text-white">Chain</span>
            </h1>
          </div>

          {/* Center: Navigation links */}
          <div className="hidden md:flex items-center space-x-8">
            <NavLink
              to="/scan"
              className={({ isActive }) =>
                `text-sm font-medium transition-colors hover:text-teal ${
                  isActive
                    ? 'text-teal underline underline-offset-4'
                    : 'text-gray-300'
                }`
              }
            >
              Scanner
            </NavLink>
            <NavLink
              to="/verify"
              className={({ isActive }) =>
                `text-sm font-medium transition-colors hover:text-teal ${
                  isActive
                    ? 'text-teal underline underline-offset-4'
                    : 'text-gray-300'
                }`
              }
            >
              Verify
            </NavLink>
            <NavLink
              to="/sentinel"
              className={({ isActive }) =>
                `text-sm font-medium transition-colors hover:text-teal ${
                  isActive
                    ? 'text-teal underline underline-offset-4'
                    : 'text-gray-300'
                }`
              }
            >
              Sentinel
            </NavLink>
          </div>

          {/* Right: Launch App button */}
          <div className="flex-shrink-0">
            <button
              onClick={() => navigate('/scan')}
              className="bg-teal text-navy px-6 py-2 rounded-md text-sm font-semibold hover:bg-teal/90 transition-colors"
            >
              Launch App
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
