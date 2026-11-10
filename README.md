# User Geo Redirect

> **This plugin has been merged into
> [CoWeb User Geo Redirect](https://github.com/yanivcoweb/coweb-user-geo-redirect),
> which works on single sites and multisite networks. This repository is
> archived and no longer maintained.** To move over, follow
> [Upgrading from User Geo Redirect](https://github.com/yanivcoweb/coweb-user-geo-redirect#upgrading-from-pw-user-geo-or-user-geo-redirect).

A WordPress **multisite** plugin that sends first-time visitors from the
network's homepage to the site that matches their country. Country detection
uses a local MaxMind GeoLite2-Country database, so no external API is called.

> Status: never released. Superseded by CoWeb User Geo Redirect.

## How it works

- In **Network Admin → Geo Redirect** you map countries to sites in the
  network, for example `IL,IT,PE` → `https://il.example.com` and
  `*` (every other country) → `https://en.example.com`.
- When a visitor who is not logged in opens a site's homepage, the plugin looks
  up their country and redirects them to the matching site.
- After the redirect it adds `?geo_redirected=1` and sets a
  `user_geo_redirected` cookie for 30 days, so each visitor is redirected only
  once.
- Inner pages, logged-in users, admin, AJAX, cron, REST and WP-CLI requests
  are never redirected.

## Requirements

- WordPress multisite (the settings page is in Network Admin)
- PHP 8.0+
- A MaxMind GeoLite2-Country database (not included, see below)

The `geoip2/geoip2` Composer package is already in `vendor/`.

## Installation

1. Copy the plugin to `wp-content/plugins/user-geo-redirect/`.
2. Download `GeoLite2-Country.mmdb` from
   [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
   (free account required) and place it in the plugin folder.
   MaxMind's licence does not allow bundling it with the plugin.
3. Network-activate the plugin.
4. Go to **Network Admin → Geo Redirect** and add your rules.

If the database is missing, the settings page shows an error and visitors are
not matched to a country.

## Show the visitor's country

Shortcode:

```text
[user_country]               → Israel
[user_country format="code"] → IL
```

PHP (in theme templates):

```php
echo ugr_get_user_country();        // Israel
echo ugr_get_user_country( 'code' ); // IL
```

## Testing

- Add `?test_country=IL` (or any ISO code, or `*`) to the homepage URL to
  simulate a country. This works when the request comes from `localhost`.
  Logged-in users, network admins included, are never redirected, so test
  while logged out.
- To test as a real visitor, use a private window or a VPN. Clear the
  `user_geo_redirected` cookie between tests, or you will not be redirected
  again.
- If the homepage is served from a full-page cache, exclude it from the cache,
  or the redirect will not run.

## Debug logging

Logging is off by default. To turn it on, add this to `wp-config.php`:

```php
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'GEO_REDIRECT_DEBUG', true );
```

Messages appear in `wp-content/debug.log` with a `[user-geo-redirect]` prefix.
They include visitor IP addresses, so turn logging off again when you are done.

## Author

Yaniv Sasson: <https://yanivsasson.com>

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).

This product includes GeoLite2 data created by MaxMind, available from
<https://www.maxmind.com>.
