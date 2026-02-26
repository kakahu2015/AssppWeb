import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { config } from '../config.js';
import { getAllTasks } from '../services/downloadManager.js';
import { buildManifest, getWhitePng } from '../services/manifestBuilder.js';

const router = Router();

function getIdParam(req: Request): string {
  const id = req.params.id;
  return Array.isArray(id) ? id[0] : id;
}

function getBaseUrl(req: Request): string {
  const configured = normalizeBaseUrl(config.publicBaseUrl);
  if (configured) return configured;

  // Trust x-forwarded-proto for protocol (safe — only affects URL scheme)
  // but use host header directly (not x-forwarded-host) to prevent open redirects
  const forwardedProto = req.headers['x-forwarded-proto'];
  const proto = forwardedProto === 'https' || req.secure ? 'https' : 'http';
  const host = req.headers['host'] || 'localhost';

  // Validate host header to prevent injection
  const sanitizedHost = host.replace(/[^\w.\-:]/g, '');

  return `${proto}://${sanitizedHost}`;
}

function normalizeBaseUrl(value?: string): string {
  if (!value) return '';
  return value.trim().replace(/\/+$/, '');
}

function joinUrl(baseUrl: string, routePath: string): string {
  const base = baseUrl.replace(/\/+$/, '');
  const suffix = routePath.replace(/^\/+/, '');
  return `${base}/${suffix}`;
}

function getInstallSecret(): string {
  return config.installUrlSecret.trim();
}

export function createInstallSignature(
  id: string,
  expires: string,
  secret: string,
): string {
  return crypto
    .createHmac('sha256', secret)
    .update(`${id}:${expires}`)
    .digest('hex');
}

export function verifyInstallSignature(
  id: string,
  expires: string,
  signature: string,
  secret: string,
): boolean {
  const expected = createInstallSignature(id, expires, secret);
  const expectedBuf = Buffer.from(expected);
  const signatureBuf = Buffer.from(signature);
  if (expectedBuf.length !== signatureBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, signatureBuf);
}

function parseQueryParam(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value;
}

function isInstallTokenValid(req: Request, id: string): boolean {
  const secret = getInstallSecret();
  if (!secret) return true;

  const expires = parseQueryParam(req.query.expires);
  const signature = parseQueryParam(req.query.sig);
  if (!expires || !signature) return false;

  const expiresMs = Number(expires);
  if (!Number.isFinite(expiresMs)) return false;
  if (Date.now() > expiresMs) return false;

  return verifyInstallSignature(id, expires, signature, secret);
}

function requireInstallToken(req: Request, res: Response, id: string): boolean {
  if (isInstallTokenValid(req, id)) return true;
  res.status(403).json({ error: 'Access denied' });
  return false;
}

function signedInstallPath(basePath: string, id: string): string {
  const secret = getInstallSecret();
  if (!secret) return basePath;

  const ttl = Math.max(60, config.installUrlTtlSeconds) * 1000;
  const expires = String(Date.now() + ttl);
  const sig = createInstallSignature(id, expires, secret);
  const joiner = basePath.includes('?') ? '&' : '?';
  return `${basePath}${joiner}expires=${encodeURIComponent(expires)}&sig=${encodeURIComponent(sig)}`;
}

// Manifest plist for iTMS installation
router.get('/install/:id/manifest.plist', (req: Request, res: Response) => {
  const id = getIdParam(req);
  if (!requireInstallToken(req, res, id)) return;

  const task = getAllTasks().find(
    (t) => t.id === id && t.status === 'completed',
  );

  if (!task || !task.filePath) {
    res.status(404).json({ error: 'Package not found' });
    return;
  }

  const baseUrl = getBaseUrl(req);
  const payloadUrl = joinUrl(baseUrl, signedInstallPath(`/api/install/${id}/payload.ipa`, id));
  const smallIconUrl = joinUrl(baseUrl, `/api/install/${id}/icon-small.png`);
  const largeIconUrl = joinUrl(baseUrl, `/api/install/${id}/icon-large.png`);

  const manifest = buildManifest(
    task.software,
    payloadUrl,
    smallIconUrl,
    largeIconUrl,
  );

  res.setHeader('Content-Type', 'application/xml');
  res.send(manifest);
});

router.get('/install/:id/url', (req: Request, res: Response) => {
  const id = getIdParam(req);
  const task = getAllTasks().find(
    (t) => t.id === id && t.status === 'completed',
  );

  if (!task || !task.filePath) {
    res.status(404).json({ error: 'Package not found' });
    return;
  }

  const baseUrl = getBaseUrl(req);
  const manifestPath = signedInstallPath(`/api/install/${id}/manifest.plist`, id);
  const manifestUrl = joinUrl(baseUrl, manifestPath);
  const installUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(
    manifestUrl,
  )}`;

  res.json({ installUrl, manifestUrl });
});

// Stream IPA payload for installation
router.get('/install/:id/payload.ipa', (req: Request, res: Response) => {
  const id = getIdParam(req);
  if (!requireInstallToken(req, res, id)) return;

  const task = getAllTasks().find(
    (t) => t.id === id && t.status === 'completed',
  );

  if (!task || !task.filePath || !fs.existsSync(task.filePath)) {
    res.status(404).json({ error: 'Package not found' });
    return;
  }

  // Verify file path is within packages directory
  const packagesBase = path.resolve(path.join(config.dataDir, 'packages'));
  const resolvedPath = path.resolve(task.filePath);
  if (!resolvedPath.startsWith(packagesBase + path.sep)) {
    res.status(403).json({ error: 'Access denied' });
    return;
  }

  res.setHeader('Content-Type', 'application/octet-stream');
  const stats = fs.statSync(resolvedPath);
  res.setHeader('Content-Length', stats.size);

  const stream = fs.createReadStream(resolvedPath);
  stream.pipe(res);
});

// Small icon placeholder (57x57)
router.get('/install/:id/icon-small.png', (_req: Request, res: Response) => {
  const png = getWhitePng();
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Content-Length', png.length);
  res.send(png);
});

// Large icon placeholder (512x512)
router.get('/install/:id/icon-large.png', (_req: Request, res: Response) => {
  const png = getWhitePng();
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Content-Length', png.length);
  res.send(png);
});

export default router;
