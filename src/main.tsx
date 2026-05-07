// FILE: src/main.tsx — App entry point with ErrorBoundary and Toaster.

import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';
import { Toaster } from 'sonner';
import ErrorBoundary from './components/ErrorBoundary';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            borderRadius: '16px',
            border: '2px solid #000',
            fontWeight: 700,
            boxShadow: '4px 4px 0 #000',
          },
        }}
      />
    </ErrorBoundary>
  </React.StrictMode>
);
