/**
 * DriftGuard Universal JavaScript/TypeScript SDK
 * ================================================
 * Drop-in cybersecurity breach prevention for ANY JavaScript application.
 *
 * Usage (Node.js / Express):
 *   const { DriftGuardClient } = require('./sdk/driftguard-sdk');
 *   const dg = new DriftGuardClient({ apiUrl: 'http://localhost:8000', apiKey: 'your-key' });
 *   dg.sendSignal('access_log', 'auth-service', { access_count: 5 });
 *
 * Usage (Express Middleware):
 *   const { driftGuardExpressMiddleware } = require('./sdk/driftguard-sdk');
 *   app.use(driftGuardExpressMiddleware({ apiUrl: 'http://localhost:8000' }));
 *
 * Usage (Next.js / Fetch-based):
 *   const dg = new DriftGuardClient({ apiUrl: 'http://localhost:8000' });
 *   await dg.sendWebhookEvent('user.login', { userId: '...', success: true });
 */

interface DriftGuardConfig {
  apiUrl: string;
  apiKey?: string;
  appId?: string;
  appName?: string;
  domain?: string;
  timeout?: number;
  flushInterval?: number;
  maxBufferSize?: number;
}

interface Signal {
  signal_type: string;
  source: string;
  data: Record<string, unknown>;
  timestamp?: string;
  metadata?: Record<string, unknown>;
}

const SIGNAL_TYPES = new Set([
  'access_log', 'audit_review', 'incident_response',
  'communication', 'approval_workflow', 'training_completion', 'custom',
]);

export class DriftGuardClient {
  private apiUrl: string;
  private apiKey?: string;
  private appId: string;
  private appName: string;
  private domain: string;
  private timeout: number;
  private buffer: Signal[] = [];
  private flushInterval: number;
  private maxBufferSize: number;
  private flushTimer?: ReturnType<typeof setInterval>;

  constructor(config: DriftGuardConfig) {
    this.apiUrl = config.apiUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.appId = config.appId || crypto.randomUUID();
    this.appName = config.appName || 'unknown';
    this.domain = config.domain || 'enterprise';
    this.timeout = config.timeout || 30000;
    this.flushInterval = config.flushInterval || 60000;
    this.maxBufferSize = config.maxBufferSize || 100;
  }

  /** Send a single signal to DriftGuard */
  async sendSignal(
    signalType: string,
    source: string,
    data: Record<string, unknown>,
    metadata?: Record<string, unknown>,
  ): Promise<unknown> {
    const payload = {
      signal_type: SIGNAL_TYPES.has(signalType) ? signalType : 'custom',
      source: `${this.appName}:${source}`,
      timestamp: new Date().toISOString(),
      data,
      domain: this.domain,
      metadata: {
        ...(metadata || {}),
        app_id: this.appId,
        app_name: this.appName,
        sdk_version: '1.0.0',
        sdk_language: 'javascript',
      },
    };
    return this.post('/api/v1/signals/ingest', payload);
  }

  /** Send a generic webhook event — DriftGuard auto-classifies it */
  async sendWebhookEvent(
    eventType: string,
    payload: Record<string, unknown>,
    sourceApp?: string,
  ): Promise<unknown> {
    return this.post('/api/v1/integrations/webhook', {
      event_type: eventType,
      payload,
      source_app: sourceApp || this.appName,
      app_id: this.appId,
      timestamp: new Date().toISOString(),
    });
  }

  /** Send batch signals */
  async sendBatch(
    signals: Array<{ signalType: string; source: string; data: Record<string, unknown> }>,
    teamId?: string,
    systemId?: string,
  ): Promise<unknown> {
    const formatted = signals.map(s => ({
      signal_type: SIGNAL_TYPES.has(s.signalType) ? s.signalType : 'custom',
      source: `${this.appName}:${s.source}`,
      timestamp: new Date().toISOString(),
      data: s.data,
      domain: this.domain,
      metadata: { app_id: this.appId, app_name: this.appName },
    }));

    return this.post('/api/v1/signals/ingest/batch', {
      signals: formatted,
      team_id: teamId,
      system_id: systemId,
      domain: this.domain,
    });
  }

  /** Register this application with DriftGuard */
  async registerApp(config: {
    appName: string;
    domain?: string;
    webhookUrl?: string;
    webhookEvents?: string[];
  }): Promise<unknown> {
    return this.post('/api/v1/integrations/apps/register', {
      app_id: this.appId,
      app_name: config.appName,
      domain: config.domain || this.domain,
      webhook_url: config.webhookUrl,
      webhook_events: config.webhookEvents || ['alert.critical', 'alert.warning'],
    });
  }

  /** Get alerts for this app */
  async getAlerts(level?: string): Promise<unknown> {
    const params = new URLSearchParams({ app_id: this.appId });
    if (level) params.set('level', level);
    return this.get(`/api/v1/alerts?${params}`);
  }

  /** Health check */
  async healthCheck(): Promise<unknown> {
    return this.get('/api/v1/health');
  }

  /** Buffer a signal for later batch send */
  bufferSignal(signalType: string, source: string, data: Record<string, unknown>): void {
    this.buffer.push({
      signal_type: SIGNAL_TYPES.has(signalType) ? signalType : 'custom',
      source: `${this.appName}:${source}`,
      data,
      timestamp: new Date().toISOString(),
      metadata: { app_id: this.appId },
    });

    if (this.buffer.length >= this.maxBufferSize) {
      this.flush();
    }
  }

  /** Start automatic buffer flushing */
  startAutoFlush(): void {
    this.flushTimer = setInterval(() => this.flush(), this.flushInterval);
  }

  /** Stop automatic buffer flushing */
  stopAutoFlush(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flush();
    }
  }

  /** Flush buffered signals */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const signals = [...this.buffer];
    this.buffer = [];

    try {
      await this.post('/api/v1/signals/ingest/batch', {
        signals,
        domain: this.domain,
      });
    } catch (e) {
      // Re-buffer on failure
      this.buffer = [...signals.slice(0, this.maxBufferSize), ...this.buffer].slice(0, this.maxBufferSize * 2);
      console.error('DriftGuard flush failed:', e);
    }
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) h['Authorization'] = `Bearer ${this.apiKey}`;
    h['X-DriftGuard-App-ID'] = this.appId;
    return h;
  }

  private async post(path: string, data: unknown): Promise<unknown> {
    const resp = await fetch(`${this.apiUrl}${path}`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(this.timeout),
    });
    if (!resp.ok) throw new Error(`DriftGuard API ${resp.status}: ${await resp.text()}`);
    return resp.json();
  }

  private async get(path: string): Promise<unknown> {
    const resp = await fetch(`${this.apiUrl}${path}`, {
      headers: this.headers(),
      signal: AbortSignal.timeout(this.timeout),
    });
    if (!resp.ok) throw new Error(`DriftGuard API ${resp.status}: ${await resp.text()}`);
    return resp.json();
  }
}


/**
 * Express.js middleware — drop-in cybersecurity monitoring for any Express app.
 *
 * Usage:
 *   const { driftGuardExpressMiddleware } = require('./driftguard-sdk');
 *   app.use(driftGuardExpressMiddleware({
 *     apiUrl: 'http://localhost:8000',
 *     appName: 'my-express-app',
 *   }));
 */
export function driftGuardExpressMiddleware(config: DriftGuardConfig) {
  const client = new DriftGuardClient(config);
  client.startAutoFlush();

  const excludePaths = new Set(['/health', '/healthz', '/ready', '/metrics', '/favicon.ico']);

  return (req: any, res: any, next: any) => {
    if (excludePaths.has(req.path)) return next();

    const start = Date.now();

    // Capture response finish
    res.on('finish', () => {
      const duration = Date.now() - start;
      const path = req.path || req.url || '/';
      const method = req.method || 'GET';
      const status = res.statusCode || 200;

      let signalType = 'access_log';
      const pathLower = path.toLowerCase();

      if (['/login', '/auth', '/token', '/session'].some(p => pathLower.includes(p))) {
        signalType = 'access_log';
      } else if (['/approve', '/workflow', '/review'].some(p => pathLower.includes(p))) {
        signalType = 'approval_workflow';
      } else if (['/audit', '/compliance'].some(p => pathLower.includes(p))) {
        signalType = 'audit_review';
      } else if (['/incident', '/alert', '/ticket'].some(p => pathLower.includes(p))) {
        signalType = 'incident_response';
      } else if (status >= 500) {
        signalType = 'incident_response';
      } else if (status === 401 || status === 403) {
        signalType = 'access_log';
      }

      const now = new Date();
      client.bufferSignal(signalType, `${method}:${path}`, {
        method,
        path,
        status_code: status,
        duration_ms: duration,
        after_hours: now.getHours() < 6 || now.getHours() > 20,
        access_type: ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method) ? 'write' : 'read',
        access_count: 1,
      });
    });

    next();
  };
}
