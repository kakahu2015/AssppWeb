export const config = {
  port: parseInt(process.env.PORT || '8080'),
  dataDir: process.env.DATA_DIR || './data',
  publicBaseUrl: process.env.PUBLIC_BASE_URL || '',
  installUrlSecret: process.env.INSTALL_URL_SECRET || '',
  installUrlTtlSeconds: parseInt(process.env.INSTALL_URL_TTL_SECONDS || '900'),
};
