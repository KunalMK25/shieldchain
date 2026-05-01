import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Navbar from './Navbar';

describe('Navbar Component', () => {
  const renderNavbar = () => {
    return render(
      <BrowserRouter>
        <Navbar />
      </BrowserRouter>
    );
  };

  test('renders ShieldChain wordmark with teal accent on Shield', () => {
    renderNavbar();
    const shieldText = screen.getByText('Shield');
    const chainText = screen.getByText('Chain');
    
    expect(shieldText).toBeInTheDocument();
    expect(chainText).toBeInTheDocument();
    expect(shieldText).toHaveClass('text-teal');
    expect(chainText).toHaveClass('text-white');
  });

  test('renders all navigation links with correct text', () => {
    renderNavbar();
    
    expect(screen.getByText('Scanner')).toBeInTheDocument();
    expect(screen.getByText('Verify')).toBeInTheDocument();
    expect(screen.getByText('Sentinel')).toBeInTheDocument();
  });

  test('renders navigation links with correct href attributes', () => {
    renderNavbar();
    
    const scannerLink = screen.getByText('Scanner').closest('a');
    const verifyLink = screen.getByText('Verify').closest('a');
    const sentinelLink = screen.getByText('Sentinel').closest('a');
    
    expect(scannerLink).toHaveAttribute('href', '/scan');
    expect(verifyLink).toHaveAttribute('href', '/verify');
    expect(sentinelLink).toHaveAttribute('href', '/sentinel');
  });

  test('renders Launch App button', () => {
    renderNavbar();
    
    const launchButton = screen.getByRole('button', { name: /launch app/i });
    expect(launchButton).toBeInTheDocument();
    expect(launchButton).toHaveClass('bg-teal', 'text-navy');
  });

  test('navbar has fixed positioning and correct styling', () => {
    const { container } = renderNavbar();
    const nav = container.querySelector('nav');
    
    expect(nav).toHaveClass('fixed', 'top-0', 'z-50', 'w-full', 'bg-navy');
  });
});
