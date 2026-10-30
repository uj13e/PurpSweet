import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import IntruderResultsWindow from "./components/IntruderResultsWindow";
import { LangProvider } from "./i18n";
import "./styles.css";

// Popped-out Intruder results window: index.html?... #intruder=<attackId>
const m = location.hash.match(/^#intruder=(.+)$/);
const root = ReactDOM.createRoot(document.getElementById("root")!);
root.render(
  <React.StrictMode>
    <LangProvider>
      <ErrorBoundary label="app">
        {m ? <IntruderResultsWindow attackId={decodeURIComponent(m[1])} /> : <App />}
      </ErrorBoundary>
    </LangProvider>
  </React.StrictMode>
);
