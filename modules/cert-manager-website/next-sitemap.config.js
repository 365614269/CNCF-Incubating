module.exports = {
  siteUrl: 'https://cert-manager.io',
  generateRobotsTxt: true,
  changefreq: 'daily',
  priority: 0.7,
  sitemapSize: 7000,
  exclude: ['[fallback]', '404', '/500', '*README', '/v*-docs', '/v*-docs/*'],
  robotsTxtOptions: {
    policies: [
      {
        userAgent: '*',
        allow: '/'
      }
    ]
  }
}
