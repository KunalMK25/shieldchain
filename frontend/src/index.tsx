import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

// Suppress the benign ResizeObserver loop error that React's dev overlay
// incorrectly treats as fatal. This is a known browser/Monaco Editor quirk.
const _origError = window.onerror;
window.onerror = (message, ...args) => {
  if (typeof message === 'string' && message.includes('ResizeObserver loop')) {
    return true; // suppress — not a real error
  }
  return _origError ? (_origError as Function)(message, ...args) : false;
};

// CRA dev overlay listens to the window 'error' event — intercept it too
window.addEventListener('error', (e) => {
  if (e.message && e.message.includes('ResizeObserver loop')) {
    e.stopImmediatePropagation();
    e.preventDefault();
  }
}, true);

// Also suppress it from the console error overlay
const _origConsoleError = console.error.bind(console);
console.error = (...args: unknown[]) => {
  if (
    typeof args[0] === 'string' &&
    args[0].includes('ResizeObserver loop')
  ) {
    return;
  }
  _origConsoleError(...args);
};

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
