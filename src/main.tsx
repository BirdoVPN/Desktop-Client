import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { TitleBar } from '@/components/TitleBar';
import './styles/globals.css';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element #root not found — index.html is missing the mount point');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <ErrorBoundary chrome={<TitleBar />}>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
