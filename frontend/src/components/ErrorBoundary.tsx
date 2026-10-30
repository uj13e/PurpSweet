import { Component, ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  label?: string;
}
interface State {
  error: Error | null;
  info: string;
}

/** Catches render/runtime errors in its subtree so one broken view can't blank
 * the whole app. Shows the error + a retry/reload instead of an empty screen. */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, info: "" };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Keep it in the console for diagnosis, but never rethrow.
    // eslint-disable-next-line no-console
    console.error("[ErrorBoundary]", this.props.label || "", error, info);
    this.setState({ info: info.componentStack || "" });
  }

  reset = () => this.setState({ error: null, info: "" });

  render() {
    if (!this.state.error) return this.props.children;
    const e = this.state.error;
    return (
      <div className="section" style={{ maxWidth: 820 }}>
        <div className="banner warn">
          <b>表示中にエラーが発生しました。</b> この画面だけの問題で、他のタブは使えます。
          «An error occurred in this view; other tabs still work.»
        </div>
        <div className="card">
          <div className="row" style={{ marginBottom: 8 }}>
            <button className="primary" onClick={this.reset}>再試行 / Retry</button>
            <button onClick={() => location.reload()}>再読み込み / Reload</button>
            {this.props.label && <span className="muted mono">{this.props.label}</span>}
          </div>
          <label>error</label>
          <pre className="raw" style={{ border: "1px solid var(--border)", borderRadius: 6, maxHeight: 180, whiteSpace: "pre-wrap" }}>
            {String(e && (e.stack || e.message || e))}
          </pre>
          {this.state.info && (
            <details style={{ marginTop: 6 }}>
              <summary className="muted">component stack</summary>
              <pre className="raw" style={{ border: "1px solid var(--border)", borderRadius: 6, maxHeight: 160, whiteSpace: "pre-wrap" }}>{this.state.info}</pre>
            </details>
          )}
        </div>
      </div>
    );
  }
}
