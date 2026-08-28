import { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught component error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#051F20] text-pine-100 flex items-center justify-center p-6">
          <div className="max-w-md w-full p-6 rounded-2xl bg-pine-900 border border-red-500/40 text-center space-y-4 shadow-2xl">
            <h2 className="text-xl font-bold text-red-300">Something went wrong</h2>
            <p className="text-xs text-pine-300">
              {this.state.error?.message || 'A visual component encountered an unexpected error.'}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-2 rounded-xl bg-pine-600 hover:bg-pine-500 text-white text-xs font-bold uppercase tracking-wider"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

