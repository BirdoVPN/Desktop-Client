import { Component, Fragment, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  /**
   * Rendered above the fallback. The ROOT boundary passes the title bar: the
   * window is frameless, so a fallback that replaced everything left a window
   * with no minimise or close control (W2-044). Inner boundaries sit below the
   * title bar and need none.
   */
  chrome?: ReactNode;
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
        <div className="flex h-full flex-col bg-black text-white">
          {this.props.chrome}
          <div className="flex flex-1 flex-col items-center justify-center gap-4">
            <p className="text-lg font-semibold">Something went wrong</p>
            {this.state.errorMessage && (
              <details className="max-w-md text-center text-xs text-white/60">
                <summary className="cursor-pointer">Details</summary>
                <p className="mt-2 wrap-break-word">{this.state.errorMessage}</p>
              </details>
            )}
            <button
              type="button"
              onClick={this.handleReset}
              className="rounded-sm bg-white/10 px-4 py-2 text-sm hover:bg-white/20"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }
    // Keyed Fragment forces a remount of the subtree on reset without
    // introducing a wrapper DOM node that could disturb the layout.
    return <Fragment key={this.state.resetKey}>{this.props.children}</Fragment>;
  }
}
