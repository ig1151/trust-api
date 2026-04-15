import { Router, Request, Response } from 'express';
import { config } from '../utils/config';
export const openapiRouter = Router();
export const docsRouter = Router();

const docsHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Trust API — Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; color: #333; }
    h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
    h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; }
    .get { background: #e3f2fd; color: #1565c0; }
    .post { background: #e8f5e9; color: #2e7d32; }
    .endpoint { background: #f5f5f5; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .path { font-family: monospace; font-size: 1rem; font-weight: bold; }
    .desc { color: #666; font-size: 0.9rem; margin-top: 0.25rem; }
    pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 8px; }
    th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
    th { background: #f5f5f5; }
  </style>
</head>
<body>
  <h1>Trust API</h1>
  <p>The only API that combines Web2 identity risk and Web3 wallet intelligence into a single unified trust score.</p>
  <p><strong>Base URL:</strong> <code>https://trust-api.onrender.com</code></p>

  <h2>Quick start</h2>
  <pre>const res = await fetch("https://trust-api.onrender.com/v1/assess", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    email: "user@example.com",
    ip: "8.8.8.8",
    wallet_address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
  })
});
const { recommendation, trust_score, trust_level } = await res.json();
if (recommendation === "block") rejectUser();
else if (recommendation === "verify") requireKYC();
else allowAccess();</pre>

  <h2>Endpoints</h2>
  <div class="endpoint">
    <div><span class="badge post">POST</span><span class="path">/v1/assess</span></div>
    <div class="desc">Assess trust — pass any combination of email, phone, IP and wallet address</div>
    <pre>curl -X POST https://trust-api.onrender.com/v1/assess \\
  -H "Content-Type: application/json" \\
  -d '{"email": "user@gmail.com", "ip": "8.8.8.8", "wallet_address": "0x..."}'</pre>
  </div>
  <div class="endpoint">
    <div><span class="badge get">GET</span><span class="path">/v1/assess</span></div>
    <div class="desc">Assess trust via query parameters</div>
    <pre>curl "https://trust-api.onrender.com/v1/assess?email=user@gmail.com&wallet_address=0x..."</pre>
  </div>

  <h2>Trust levels</h2>
  <table>
    <tr><th>Level</th><th>Score range</th><th>Meaning</th></tr>
    <tr><td>trusted</td><td>75–100</td><td>Low risk — safe to allow</td></tr>
    <tr><td>neutral</td><td>50–74</td><td>Some signals — proceed with caution</td></tr>
    <tr><td>suspicious</td><td>25–49</td><td>Multiple risk signals — require verification</td></tr>
    <tr><td>blocked</td><td>0–24</td><td>High risk — block or reject</td></tr>
  </table>

  <h2>Supported signals</h2>
  <table>
    <tr><th>Source</th><th>Signals checked</th></tr>
    <tr><td>Email</td><td>Disposable, invalid, role-based, MX records, business detection</td></tr>
    <tr><td>Phone</td><td>VoIP, fake numbers, invalid format, line type</td></tr>
    <tr><td>IP</td><td>Tor, proxy, VPN, datacenter/hosting detection</td></tr>
    <tr><td>Wallet</td><td>Mixer interactions, high frequency trading, large transfers, wallet age, dormant detection</td></tr>
  </table>

  <h2>Supported chains</h2>
  <table>
    <tr><th>Chain</th><th>Auto-detected from</th></tr>
    <tr><td>Ethereum</td><td>0x + 40 hex chars</td></tr>
    <tr><td>Solana</td><td>Base58 32-44 chars</td></tr>
    <tr><td>BNB Chain</td><td>0x + 40 hex chars (specify chain=bnb)</td></tr>
    <tr><td>XRP</td><td>r + base58 24-34 chars</td></tr>
  </table>

  <h2>OpenAPI Spec</h2>
  <p><a href="/openapi.json">Download openapi.json</a></p>
</body>
</html>`;

docsRouter.get('/', (_req: Request, res: Response) => { res.setHeader('Content-Type', 'text/html'); res.send(docsHtml); });

openapiRouter.get('/', (_req: Request, res: Response) => {
  res.status(200).json({
    openapi: '3.0.3',
    info: { title: 'Trust API', version: '1.0.0', description: 'Web2 identity risk + Web3 wallet intelligence in one unified trust score.' },
    servers: [{ url: 'https://trust-api.onrender.com', description: 'Production' }, { url: `http://localhost:${config.server.port}`, description: 'Local' }],
    paths: {
      '/v1/health': { get: { summary: 'Health check', operationId: 'getHealth', responses: { '200': { description: 'OK' } } } },
      '/v1/assess': {
        post: { summary: 'Assess trust', operationId: 'assessPost', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/TrustRequest' }, examples: { web2_only: { summary: 'Web2 only', value: { email: 'user@gmail.com', phone: '+14155552671', ip: '8.8.8.8' } }, web3_only: { summary: 'Web3 only', value: { wallet_address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e' } }, combined: { summary: 'Combined Web2 + Web3', value: { email: 'user@company.com', ip: '8.8.8.8', wallet_address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e' } } } } } }, responses: { '200': { description: 'Trust assessment' }, '422': { description: 'Validation error' } } },
        get: { summary: 'Assess trust via GET', operationId: 'assessGet', parameters: [{ name: 'email', in: 'query', schema: { type: 'string' } }, { name: 'ip', in: 'query', schema: { type: 'string' } }, { name: 'wallet_address', in: 'query', schema: { type: 'string' } }], responses: { '200': { description: 'Trust assessment' } } },
      },
    },
    components: {
      schemas: {
        TrustRequest: { type: 'object', properties: { email: { type: 'string' }, phone: { type: 'string' }, ip: { type: 'string' }, wallet_address: { type: 'string' }, wallet_chain: { type: 'string', enum: ['ethereum', 'solana', 'bnb', 'xrp', 'auto'], default: 'auto' }, country_code: { type: 'string' } }, minProperties: 1 },
      },
    },
  });
});
