import { Component, Fragment, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  errorMessage?: string;
  resetKey: number;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, resetKey: 0 };

  static getDerivedStateFromError(error: unknown): Partial<State> {
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    return { hasError: true, errorMessage };
  }

  componentDidCatch(error: unknown) {
    // Log in all environments so production crashes remain diagnosable.
    console.error('[ErrorBoundary] Unhandled React error:', error);
  }

  private handleReset = () => {
    // Bump resetKey to force a remount of the subtree, so a recovered
    // (transient) error actually re-runs the render path instead of
    // immediately re-throwing the stale tree.
    this.setState((prev) => ({
      hasError: false,
      errorMessage: undefined,
      resetKey: prev.resetKey + 1,
    }));
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-screen flex-col items-center justify-center gap-4 bg-black text-white">
          <p className="text-lg font-semibold">Something went wrong</p>
          {this.state.errorMessage && (
            <details className="max-w-md text-center text-xs text-white/60">
              <summary className="cursor-pointer">Details</summary>
              <p className="mt-2 break-words">{this.state.errorMessage}</p>
            </details>
          )}
          <button
            onClick={this.handleReset}
            className="rounded bg-white/10 px-4 py-2 text-sm hover:bg-white/20"
          >
            Try again
          </button>
        </div>
      );
    }
    // Keyed Fragment forces a remount of the subtree on reset without
    // introducing a wrapper DOM node that could disturb the layout.
    return <Fragment key={this.state.resetKey}>{this.props.children}</Fragment>;
  }
}
