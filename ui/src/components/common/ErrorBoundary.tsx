import React from "react";

interface Props {
  children: React.ReactNode;
}

interface State {
  error: Error | null;
}

// ErrorBoundary turns the worst failure mode of a single-page app into a readable
// one. Without it, an exception anywhere in the tree unmounts everything and the
// operator sees a blank page with no clue, which is exactly what happened when the
// dashboard first ran against the real API.
export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    // Keep the console entry: it is what a bug report needs, and the UI alone
    // cannot tell how deep the failure was.
    console.error("dashboard render error", error, info.componentStack);
  }

  render(): React.ReactNode {
    if (this.state.error) {
      return (
        <section className="view-stack" role="alert">
          <h1 className="view-title">This view could not be rendered</h1>
          <p className="view-subtitle">
            The dashboard hit an error instead of showing a blank page. The message is below so it
            can be reported; the rest of the console keeps working after a reload.
          </p>
          <pre className="alert alert-error error-details">{this.state.error.message}</pre>
          <div>
            <button type="button" className="btn-secondary" onClick={() => window.location.reload()}>
              Reload the dashboard
            </button>
          </div>
        </section>
      );
    }
    return this.props.children;
  }
}
