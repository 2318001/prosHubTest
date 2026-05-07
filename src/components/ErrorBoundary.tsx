// FILE: src/components/ErrorBoundary.tsx — Catches React render errors.

/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';

export default class ErrorBoundary extends React.Component<any, any> {
  constructor(props: any) {
    super(props);
    (this as any).state = { hasError: false, error: undefined };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: any) {
    console.error('ErrorBoundary caught:', error, info);
  }

  render() {
    if ((this as any).state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center p-6 bg-paper">
          <div className="card-brutal p-8 sm:p-12 max-w-md w-full text-center">
            <div className="text-5xl mb-6">⚡</div>
            <h1 className="text-2xl font-bold mb-3">Something went wrong</h1>
            <p className="text-muted font-medium text-sm mb-6">
              {(this as any).state.error?.message || 'An unexpected error occurred.'}
            </p>
            <button
              onClick={() => { (this as any).setState({ hasError: false }); window.location.reload(); }}
              className="btn-primary py-3 px-8"
            >
              Reload App
            </button>
          </div>
        </div>
      );
    }
    return (this as any).props.children;
  }
}
