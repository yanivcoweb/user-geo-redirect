<?php
/**
 * Plugin Name:       User Geo Redirect
 * Plugin URI:        https://coweb.co.il/
 * Description:       Detects a user's country based on IP and redirects them to a specific URL. Includes AJAX verification to bypass caching issues.
 * Version:           1.0.0
 * Author:            Yaniv Sasson
 * Author URI:        https://yanivsasson.com/
 * License:           GPLv2 or later
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       user-geo-redirect
 */

// Define debug constant
if (!defined('GEO_REDIRECT_DEBUG')) {
    // Don't log during cron requests
    $is_cron = (defined('DOING_CRON') && DOING_CRON) ||
                (strpos($_SERVER['REQUEST_URI'] ?? '', 'wp-cron.php') !== false);
    define('GEO_REDIRECT_DEBUG', !$is_cron);
}

if (GEO_REDIRECT_DEBUG) {
    error_log('user-geo-redirect.php loaded - ' . $_SERVER['REQUEST_URI']);
}

use GeoIp2\Database\Reader;

// מונע גישה ישירה לקובץ
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// טוען את הקבצים של Composer
require_once __DIR__ . '/vendor/autoload.php';

/**
 * קלאס שמטפל בזיהוי המיקום של המשתמש לפי ה-IP שלו וביצוע ההפניה.
 */
final class User_Geo_Redirect {

    /**
     * @var object המחזיק את המופע היחיד של הקלאס (Singleton).
     */
    private static $instance = null;

    /**
     * @var string הנתיב לקובץ ה-mmdb.
     */
    private $database_path;

    /**
     * @var array מערך הכללים להפניה, המבוסס על קוד מדינה.
     */
    private $redirect_rules = [];

    /**
     * קונסטרוקטור פרטי כדי למנוע יצירת אובייקטים ישירה.
     */
    private function __construct() {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - __construct');
        }
        $this->database_path = plugin_dir_path( __FILE__ ) . 'GeoLite2-Country.mmdb';
        $this->load_redirect_rules();
        $this->register_hooks();
    }

    /**
     * מחזירה את המופע היחיד של הקלאס (תבנית Singleton).
     *
     * @return User_Geo_Redirect
     */
    public static function instance(): User_Geo_Redirect {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - instance');
        }
        if ( is_null( self::$instance ) ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * רושמת את כל ההוקים הנדרשים לתוסף.
     *
     * @return void
     */
    private function register_hooks(): void {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - register_hooks');
        }
        // Start session if not already started
        add_action( 'init', [ $this, 'start_session' ], 1 );
        add_shortcode( 'user_country', [ $this, 'display_country_shortcode' ] );
        add_action( 'init', [ $this, 'geo_redirect' ] );
        // add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
        // add_action( 'wp_ajax_verify_country', [ $this, 'ajax_verify_country' ] );
        // add_action( 'wp_ajax_nopriv_verify_country', [ $this, 'ajax_verify_country' ] );

        if ( is_multisite() ) {
            add_action( 'network_admin_menu', [ $this, 'add_network_admin_menu' ] );
            add_action( 'network_admin_edit_ugr_save_settings', [ $this, 'save_network_settings' ] );
        }
    }

    /**
     * Start PHP session if not already started
     *
     * @return void
     */
    public function start_session(): void {
        if ( !session_id() && !headers_sent() ) {
            // Configure session to work across all subdomains
            $host = $_SERVER['HTTP_HOST'] ?? '';
            // Extract root domain (e.g., webdevtest.co.il from he.webdevtest.co.il)
            // For multi-level TLDs like .co.il, we need to handle them properly
            $domain_parts = explode('.', $host);
            if (count($domain_parts) >= 4) {
                // e.g., he.webdevtest.co.il -> .webdevtest.co.il (last 3 parts)
                $session_domain = '.' . $domain_parts[count($domain_parts) - 3] . '.' . $domain_parts[count($domain_parts) - 2] . '.' . $domain_parts[count($domain_parts) - 1];
            } elseif (count($domain_parts) == 3) {
                // e.g., webdevtest.co.il -> .webdevtest.co.il
                $session_domain = '.' . $host;
            } else {
                // e.g., localhost or example.com -> .localhost or .example.com
                $session_domain = '.' . $host;
            }

            // Set session cookie parameters to work across subdomains
            session_set_cookie_params([
                'lifetime' => 0, // Until browser closes
                'path' => '/',
                'domain' => $session_domain,
                'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
                'httponly' => true,
                'samesite' => 'Lax'
            ]);

            session_start();

            if (GEO_REDIRECT_DEBUG) {
                error_log('Session started with domain: ' . $session_domain);
            }
        }
    }

    /**
     * מבצע את ההפניה הראשונית בטעינת הדף.
     *
     * @return void
     */
    public function geo_redirect(): void {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - geo_redirect');
        }

        // Log all cookies for debugging
        error_log('All cookies at start: ' . print_r($_COOKIE, true));

        // If user was just redirected (has geo_redirected parameter), set cookie and skip
        // This must happen BEFORE any other checks
        if ( isset( $_GET['geo_redirected'] ) ) {
            error_log('User has geo_redirected parameter, setting cookie and skipping redirect');
            $thirty_days = 30 * DAY_IN_SECONDS;
            $host = $_SERVER['HTTP_HOST'] ?? '';
            // Extract root domain (e.g., webdevtest.co.il from he.webdevtest.co.il)
            // For multi-level TLDs like .co.il, we need to handle them properly
            $domain_parts = explode('.', $host);
            if (count($domain_parts) >= 4) {
                // e.g., he.webdevtest.co.il -> .webdevtest.co.il (last 3 parts)
                $cookie_domain = '.' . $domain_parts[count($domain_parts) - 3] . '.' . $domain_parts[count($domain_parts) - 2] . '.' . $domain_parts[count($domain_parts) - 1];
            } elseif (count($domain_parts) == 3) {
                // e.g., webdevtest.co.il -> .webdevtest.co.il
                $cookie_domain = '.' . $host;
            } else {
                // e.g., localhost or example.com -> .localhost or .example.com
                $cookie_domain = '.' . $host;
            }

            // Set the cookie with proper headers
            $cookie_set = setcookie( 'user_geo_redirected', '1', [
                'expires' => time() + $thirty_days,
                'path' => '/',
                'domain' => $cookie_domain,
                'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
                'httponly' => true,
                'samesite' => 'Lax'
            ]);

            error_log('Cookie set for domain: ' . $cookie_domain . ' (success: ' . ($cookie_set ? 'yes' : 'no') . ')');

            // Also set $_COOKIE immediately for this request
            $_COOKIE['user_geo_redirected'] = '1';
            return;
        }

        // Check if user has already been redirected (cookie check)
        // This check should happen BEFORE checking if on homepage
        if ( isset( $_COOKIE['user_geo_redirected'] ) ) {
            error_log('User already redirected (cookie found), skipping redirect');
            return;
        }

        // Get the current full URL
        $current_url = ( ( isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ) ? 'https' : 'http' );
        $current_url .= '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        // Remove query string and fragment
        $current_url_no_query = strtok($current_url, '?#');
        // Normalize both URLs (remove trailing slashes and www prefix for consistency)
        $current_url_no_query = untrailingslashit($current_url_no_query);
        $current_url_no_query = str_replace('://www.', '://', $current_url_no_query);
        $home_url_normalized  = untrailingslashit( home_url('/') );
        $home_url_normalized  = str_replace('://www.', '://', $home_url_normalized);

        error_log('$current_url_no_query:'.$current_url_no_query);
        error_log('$home_url_normalized:'.$home_url_normalized);

        if ( $current_url_no_query === $home_url_normalized ) {

            $user_ip = $this->get_user_ip();
            error_log('User IP: ' . $user_ip);
            $user_country_code = $this->get_country_code_from_ip( $user_ip );
            error_log('Detected country code: ' . ($user_country_code ?? 'NULL'));
            $redirect_url = $this->get_redirect_url( $user_country_code );
            error_log('Redirect URL for country ' . ($user_country_code ?? 'NULL') . ': ' . ($redirect_url ?? 'NULL'));
            // בודק אם יש כתובת הפניה ושהיא שונה מהנוכחית.
            if ( ! $redirect_url || $current_url_no_query === $redirect_url ) {
                return;
            }

            if ( $redirect_url ) {
                error_log('$redirect_url:'.$redirect_url);
                error_log($redirect_url);
                // Set session immediately before redirect
                $_SESSION['user_geo_redirected'] = '1';
                // Preserve GET parameters from current request
                $query_args = $_GET;
                // Add the custom parameter
                $query_args['geo_redirected'] = 1;
                // Add all query args to the redirect URL
                $redirect_url = add_query_arg( $query_args, $redirect_url );
                // Set cookie for 30 days to remember user has been redirected
                // Cookie domain: use the root domain to work across all subdomains
                $thirty_days = 30 * DAY_IN_SECONDS;
                $host = $_SERVER['HTTP_HOST'] ?? '';
                // Extract root domain (e.g., webdevtest.co.il from he.webdevtest.co.il)
                // For multi-level TLDs like .co.il, we need to handle them properly
                $domain_parts = explode('.', $host);
                if (count($domain_parts) >= 4) {
                    // e.g., he.webdevtest.co.il -> .webdevtest.co.il (last 3 parts)
                    $cookie_domain = '.' . $domain_parts[count($domain_parts) - 3] . '.' . $domain_parts[count($domain_parts) - 2] . '.' . $domain_parts[count($domain_parts) - 1];
                } elseif (count($domain_parts) == 3) {
                    // e.g., webdevtest.co.il -> .webdevtest.co.il
                    $cookie_domain = '.' . $host;
                } else {
                    // e.g., localhost or example.com -> .localhost or .example.com
                    $cookie_domain = '.' . $host;
                }
                setcookie( 'user_geo_redirected', '1', time() + $thirty_days, '/', $cookie_domain, false, true );
                error_log('Performing redirect with session and cookie set');
                wp_redirect( $redirect_url, 302 );
                exit;
            }
        }
    }

    /**
     * מטעין את הסקריפטים והסגנונות של התוסף.
     *
     * @return void
     */
    public function enqueue_scripts(): void {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - enqueue_scripts');
        }
        /*
        if ( is_admin() ) {
            return;
        }

        wp_enqueue_script( 'user-geo-ajax', plugin_dir_url( __FILE__ ) . 'assets/user-geo.js', ['jquery'], '1.0', true );
        wp_localize_script( 'user-geo-ajax', 'user_geo_vars', [
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'initial_country_code' => $this->get_country_code_from_ip( $this->get_user_ip() ),
        ]);
        */
    }

    /**
     * פונקציה שמטפלת בקריאת AJAX ומחזירה את קוד המדינה.
     *
     * @return void
     */
    public function ajax_verify_country(): void {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - ajax_verify_country');
        }
        /*
        $country_code = $this->get_country_code_from_ip( $this->get_user_ip() );
        wp_send_json_success( [ 'country_code' => $country_code ] );
        wp_die();
        */
    }

    /**
     * משיגה את כתובת ה-IP של המשתמש בצורה מאובטחת.
     *
     * @return string|false
     */
    private function get_user_ip(): string|false {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - get_user_ip');
        }
        $ip = false;
        if ( isset( $_SERVER['HTTP_CLIENT_IP'] ) ) {
            $ip = sanitize_text_field( $_SERVER['HTTP_CLIENT_IP'] );
        } elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ip = sanitize_text_field( $_SERVER['HTTP_X_FORWARDED_FOR'] );
        } elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( $_SERVER['REMOTE_ADDR'] );
        }
        return $ip;
    }

    /**
     * מחלצת את קוד המדינה מתוך קובץ ה-GeoLite2.
     *
     * @param string $ip כתובת ה-IP של המשתמש.
     * @return string|null
     */
    private function get_country_code_from_ip( string $ip ): ?string {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - get_country_code_from_ip');
        }

        // Testing mode: Allow overriding country via URL parameter
        // For localhost/development: works for anyone
        // For production: only works for network admins
        $is_localhost = in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1', 'localhost']);
        if ( isset( $_GET['test_country'] ) && ($is_localhost || current_user_can( 'manage_network_options' )) ) {
            $test_country = strtoupper( sanitize_text_field( $_GET['test_country'] ) );
            if ( $test_country === '*' || preg_match( '/^[A-Z]{2}$/', $test_country ) ) {
                error_log( 'Testing mode: Using country code ' . $test_country );
                return $test_country;
            }
        }

        try {
            $reader = new Reader( $this->database_path );
            $record = $reader->country( $ip );
            return $record->country->isoCode;
        } catch ( \Exception $e ) {
            error_log( 'GeoIP Error: ' . $e->getMessage() );
            return null;
        }
    }

    /**
     * מוצאת את כתובת ההפניה המתאימה לפי קוד המדינה.
     *
     * @param string|null $country_code קוד המדינה של המשתמש.
     * @return string|null
     */
    private function get_redirect_url( ?string $country_code ): ?string {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - get_redirect_url');
        }
        if ( isset( $this->redirect_rules[ $country_code ] ) ) {
            return $this->redirect_rules[ $country_code ];
        }
        return $this->redirect_rules['*'] ?? null;
    }

    /**
     * פונקציית הקוד הקצר (shortcode) שמציגה את שם המדינה.
     *
     * @param array $atts Shortcode attributes (format: 'code' or 'name')
     * @return string
     */
    public function display_country_shortcode( $atts = [] ): string {
        if (GEO_REDIRECT_DEBUG) {
            error_log('User_Geo_Redirect - display_country_shortcode');
        }

        $atts = shortcode_atts( [
            'format' => 'name', // 'name' or 'code'
        ], $atts );

        $user_ip = $this->get_user_ip();
        if ( ! $user_ip ) {
            return '';
        }

        $country_code = $this->get_country_code_from_ip( $user_ip );
        if ( ! $country_code ) {
            return '';
        }

        if ( $atts['format'] === 'code' ) {
            return $country_code;
        }

        // Return country name
        return $this->get_country_name_from_code( $country_code );
    }

    /**
     * מחזירה את שם המדינה לפי קוד המדינה.
     *
     * @param string $country_code קוד המדינה (ISO 2-letter code)
     * @return string
     */
    private function get_country_name_from_code( string $country_code ): string {
        try {
            $reader = new Reader( $this->database_path );
            // We need a valid IP from that country to get the name
            // Instead, we'll use a static array of country names
            $countries = [
                'AD' => 'Andorra', 'AE' => 'United Arab Emirates', 'AF' => 'Afghanistan',
                'AG' => 'Antigua and Barbuda', 'AL' => 'Albania', 'AM' => 'Armenia',
                'AR' => 'Argentina', 'AT' => 'Austria', 'AU' => 'Australia',
                'AZ' => 'Azerbaijan', 'BA' => 'Bosnia and Herzegovina', 'BD' => 'Bangladesh',
                'BE' => 'Belgium', 'BG' => 'Bulgaria', 'BR' => 'Brazil',
                'BY' => 'Belarus', 'CA' => 'Canada', 'CH' => 'Switzerland',
                'CL' => 'Chile', 'CN' => 'China', 'CO' => 'Colombia',
                'CR' => 'Costa Rica', 'CY' => 'Cyprus', 'CZ' => 'Czech Republic',
                'DE' => 'Germany', 'DK' => 'Denmark', 'DO' => 'Dominican Republic',
                'DZ' => 'Algeria', 'EC' => 'Ecuador', 'EE' => 'Estonia',
                'EG' => 'Egypt', 'ES' => 'Spain', 'FI' => 'Finland',
                'FR' => 'France', 'GB' => 'United Kingdom', 'GE' => 'Georgia',
                'GR' => 'Greece', 'HK' => 'Hong Kong', 'HR' => 'Croatia',
                'HU' => 'Hungary', 'ID' => 'Indonesia', 'IE' => 'Ireland',
                'IL' => 'Israel', 'IN' => 'India', 'IQ' => 'Iraq',
                'IR' => 'Iran', 'IS' => 'Iceland', 'IT' => 'Italy',
                'JO' => 'Jordan', 'JP' => 'Japan', 'KE' => 'Kenya',
                'KR' => 'South Korea', 'KW' => 'Kuwait', 'KZ' => 'Kazakhstan',
                'LB' => 'Lebanon', 'LT' => 'Lithuania', 'LU' => 'Luxembourg',
                'LV' => 'Latvia', 'MA' => 'Morocco', 'MX' => 'Mexico',
                'MY' => 'Malaysia', 'NG' => 'Nigeria', 'NL' => 'Netherlands',
                'NO' => 'Norway', 'NZ' => 'New Zealand', 'OM' => 'Oman',
                'PE' => 'Peru', 'PH' => 'Philippines', 'PK' => 'Pakistan',
                'PL' => 'Poland', 'PT' => 'Portugal', 'QA' => 'Qatar',
                'RO' => 'Romania', 'RS' => 'Serbia', 'RU' => 'Russia',
                'SA' => 'Saudi Arabia', 'SE' => 'Sweden', 'SG' => 'Singapore',
                'SI' => 'Slovenia', 'SK' => 'Slovakia', 'TH' => 'Thailand',
                'TN' => 'Tunisia', 'TR' => 'Turkey', 'TW' => 'Taiwan',
                'UA' => 'Ukraine', 'US' => 'United States', 'UY' => 'Uruguay',
                'VE' => 'Venezuela', 'VN' => 'Vietnam', 'ZA' => 'South Africa',
            ];

            return $countries[ $country_code ] ?? $country_code;
        } catch ( \Exception $e ) {
            return $country_code;
        }
    }

    /**
     * טוען את כללי ההפניה מההגדרות של הרשת.
     *
     * @return void
     */
    private function load_redirect_rules(): void {
        $saved_rules = get_site_option( 'ugr_redirect_rules', [] );

        if ( ! empty( $saved_rules ) && is_array( $saved_rules ) ) {
            $this->redirect_rules = $saved_rules;
        }
    }

    /**
     * מוסיף תפריט לניהול רשת.
     *
     * @return void
     */
    public function add_network_admin_menu(): void {
        add_menu_page(
            'Geo Redirect Settings',
            'Geo Redirect',
            'manage_network_options',
            'user-geo-redirect',
            [ $this, 'render_admin_page' ],
            'dashicons-admin-site-alt3',
            30
        );
    }

    /**
     * מציג את דף הניהול.
     *
     * @return void
     */
    public function render_admin_page(): void {
        if ( ! current_user_can( 'manage_network_options' ) ) {
            wp_die( 'You do not have permission to access this page.' );
        }

        $sites = get_sites();
        $saved_rules = get_site_option( 'ugr_redirect_rules', [] );

        // Group countries by site URL for display
        $display_rules = [];
        if ( ! empty( $saved_rules ) ) {
            foreach ( $saved_rules as $country_code => $site_url ) {
                if ( ! isset( $display_rules[ $site_url ] ) ) {
                    $display_rules[ $site_url ] = [];
                }
                $display_rules[ $site_url ][] = $country_code;
            }
        }

        ?>
        <div class="wrap">
            <h1>User Geo Redirect Settings</h1>

            <form method="post" action="edit.php?action=ugr_save_settings">
                <?php wp_nonce_field( 'ugr_save_settings_nonce' ); ?>

                <table class="wp-list-table widefat fixed striped" id="ugr-rules-table">
                    <thead>
                        <tr>
                            <th style="width: 40%;">Site</th>
                            <th style="width: 50%;">Countries (comma-separated ISO codes or * for all)</th>
                            <th style="width: 10%;">Action</th>
                        </tr>
                    </thead>
                    <tbody id="ugr-rules-body">
                        <?php
                        if ( ! empty( $display_rules ) ) :
                            foreach ( $display_rules as $site_url => $country_codes ) :
                                $countries_string = implode( ',', $country_codes );
                                ?>
                                <tr>
                                    <td>
                                        <select name="ugr_rules[site][]" class="regular-text" required>
                                            <option value="">Select a site...</option>
                                            <?php foreach ( $sites as $site ) :
                                                $site_url_option = untrailingslashit( get_site_url( $site->blog_id ) );
                                            ?>
                                                <option value="<?php echo esc_attr( $site_url_option ); ?>" <?php selected( $site_url, $site_url_option ); ?>>
                                                    <?php echo esc_html( $site_url_option ); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </td>
                                    <td>
                                        <input type="text" name="ugr_rules[countries][]" value="<?php echo esc_attr( $countries_string ); ?>" class="regular-text" placeholder="IL,IT,PE or *" required />
                                        <p class="description">Use ISO 2-letter country codes (e.g., IL,IT,PE) or * for all countries</p>
                                    </td>
                                    <td>
                                        <button type="button" class="button ugr-remove-rule">Remove</button>
                                    </td>
                                </tr>
                                <?php
                            endforeach;
                        endif;
                        ?>
                    </tbody>
                </table>

                <p>
                    <button type="button" id="ugr-add-rule" class="button">Add New Rule</button>
                </p>

                <p class="submit">
                    <input type="submit" name="submit" id="submit" class="button button-primary" value="Save Settings">
                </p>
            </form>

            <div class="ugr-instructions-wrapper">
                <h2 class="nav-tab-wrapper">
                    <a href="#usage-tab" class="nav-tab nav-tab-active">Usage Instructions</a>
                    <a href="#testing-tab" class="nav-tab">Testing Instructions</a>
                    <a href="#countries-tab" class="nav-tab">Country Codes</a>
                </h2>

                <div id="usage-tab" class="ugr-tab-content ugr-tab-active">
                    <h3>How to Display User's Country in Your Theme</h3>

                    <h4>Method 1: Using Shortcode (in posts/pages)</h4>
                    <p>Add this shortcode to any post, page, or widget:</p>
                    <ul>
                        <li><strong>Show country name:</strong> <code>[user_country]</code> or <code>[user_country format="name"]</code>
                            <br><span class="description">Example output: "Israel" or "United States"</span>
                        </li>
                        <li><strong>Show country code:</strong> <code>[user_country format="code"]</code>
                            <br><span class="description">Example output: "IL" or "US"</span>
                        </li>
                    </ul>

                    <h4>Method 2: Using PHP Function (in theme files)</h4>
                    <p>Add this code to your theme templates (header.php, footer.php, etc.):</p>
                    <ul>
                        <li><strong>Show country name:</strong>
                            <pre><code>&lt;?php echo ugr_get_user_country(); ?&gt;</code></pre>
                            <span class="description">Example output: "Israel" or "United States"</span>
                        </li>
                        <li><strong>Show country code:</strong>
                            <pre><code>&lt;?php echo ugr_get_user_country('code'); ?&gt;</code></pre>
                            <span class="description">Example output: "IL" or "US"</span>
                        </li>
                    </ul>

                    <h4>Example Usage in Theme:</h4>
                    <pre><code>&lt;p&gt;Welcome visitor from &lt;?php echo ugr_get_user_country(); ?&gt;!&lt;/p&gt;</code></pre>
                    <p class="description">This will display: "Welcome visitor from Israel!" or "Welcome visitor from United States!"</p>
                </div>

                <div id="testing-tab" class="ugr-tab-content">
                    <h3>Testing Instructions</h3>

                    <h4>1. Setup Your Redirect Rules</h4>
                    <p>First, add some test rules above. For example:</p>
                    <ul>
                        <li>Site: <code>http://yanivsasson.local</code> → Countries: <code>IL,IT,PE</code></li>
                        <li>Site: <code>http://yanivsasson.localcom</code> → Countries: <code>*</code></li>
                    </ul>

                    <h4>2. Testing with URL Parameter (Easiest Method)</h4>
                    <p>The plugin includes a testing feature that lets you simulate different countries using a URL parameter. This only works when you're logged in as a network admin.</p>

                    <p><strong>How to test:</strong></p>
                    <ol>
                        <li>Log in as network admin</li>
                        <li>Visit your homepage with a test country parameter:
                            <ul>
                                <li>Test Israel redirect: <code>http://yanivsasson.local/?test_country=IL</code></li>
                                <li>Test Italy redirect: <code>http://yanivsasson.local/?test_country=IT</code></li>
                                <li>Test Peru redirect: <code>http://yanivsasson.local/?test_country=PE</code></li>
                                <li>Test wildcard (all other countries): <code>http://yanivsasson.local/?test_country=US</code></li>
                            </ul>
                        </li>
                        <li>Check the debug log at <code>C:\wamp64\www\yanivsasson\wp-content\debug.log</code> to see what's happening</li>
                    </ol>

                    <h4>3. Testing with VPN (Real-World Test)</h4>
                    <p>For more realistic testing:</p>
                    <ol>
                        <li>Use a VPN service and connect to different countries</li>
                        <li>Visit your site without logging in</li>
                        <li>It should redirect based on the VPN country</li>
                    </ol>

                    <h4>4. Check Debug Logs</h4>
                    <p>Your plugin has debug logging enabled. Check <code>C:\wamp64\www\yanivsasson\wp-content\debug.log</code> to see:</p>
                    <ul>
                        <li>What country was detected</li>
                        <li>What redirect URL was determined</li>
                        <li>Whether redirect happened</li>
                    </ul>

                    <h4>Important Testing Notes:</h4>
                    <ul>
                        <li>The <code>test_country</code> parameter <strong>only works for logged-in network admins</strong> (for security)</li>
                        <li>The plugin only redirects on the <strong>homepage</strong> (not sub-pages)</li>
                        <li>It <strong>won't redirect</strong> if you're logged in as a regular user (you need to log out or use incognito mode after testing with test_country parameter)</li>
                        <li>Each redirect adds <code>?geo_redirected=1</code> to prevent redirect loops</li>
                    </ul>
                </div>

                <div id="countries-tab" class="ugr-tab-content">
                    <h3>Country Code Reference</h3>
                    <p>Common ISO 2-letter country codes:</p>
                    <div style="column-count: 4; column-gap: 20px;">
                    <div><strong>AD</strong> - Andorra</div>
                    <div><strong>AE</strong> - United Arab Emirates</div>
                    <div><strong>AF</strong> - Afghanistan</div>
                    <div><strong>AG</strong> - Antigua and Barbuda</div>
                    <div><strong>AL</strong> - Albania</div>
                    <div><strong>AM</strong> - Armenia</div>
                    <div><strong>AR</strong> - Argentina</div>
                    <div><strong>AT</strong> - Austria</div>
                    <div><strong>AU</strong> - Australia</div>
                    <div><strong>AZ</strong> - Azerbaijan</div>
                    <div><strong>BA</strong> - Bosnia and Herzegovina</div>
                    <div><strong>BD</strong> - Bangladesh</div>
                    <div><strong>BE</strong> - Belgium</div>
                    <div><strong>BG</strong> - Bulgaria</div>
                    <div><strong>BR</strong> - Brazil</div>
                    <div><strong>BY</strong> - Belarus</div>
                    <div><strong>CA</strong> - Canada</div>
                    <div><strong>CH</strong> - Switzerland</div>
                    <div><strong>CL</strong> - Chile</div>
                    <div><strong>CN</strong> - China</div>
                    <div><strong>CO</strong> - Colombia</div>
                    <div><strong>CR</strong> - Costa Rica</div>
                    <div><strong>CY</strong> - Cyprus</div>
                    <div><strong>CZ</strong> - Czech Republic</div>
                    <div><strong>DE</strong> - Germany</div>
                    <div><strong>DK</strong> - Denmark</div>
                    <div><strong>DO</strong> - Dominican Republic</div>
                    <div><strong>DZ</strong> - Algeria</div>
                    <div><strong>EC</strong> - Ecuador</div>
                    <div><strong>EE</strong> - Estonia</div>
                    <div><strong>EG</strong> - Egypt</div>
                    <div><strong>ES</strong> - Spain</div>
                    <div><strong>FI</strong> - Finland</div>
                    <div><strong>FR</strong> - France</div>
                    <div><strong>GB</strong> - United Kingdom</div>
                    <div><strong>GE</strong> - Georgia</div>
                    <div><strong>GR</strong> - Greece</div>
                    <div><strong>HK</strong> - Hong Kong</div>
                    <div><strong>HR</strong> - Croatia</div>
                    <div><strong>HU</strong> - Hungary</div>
                    <div><strong>ID</strong> - Indonesia</div>
                    <div><strong>IE</strong> - Ireland</div>
                    <div><strong>IL</strong> - Israel</div>
                    <div><strong>IN</strong> - India</div>
                    <div><strong>IQ</strong> - Iraq</div>
                    <div><strong>IR</strong> - Iran</div>
                    <div><strong>IS</strong> - Iceland</div>
                    <div><strong>IT</strong> - Italy</div>
                    <div><strong>JO</strong> - Jordan</div>
                    <div><strong>JP</strong> - Japan</div>
                    <div><strong>KE</strong> - Kenya</div>
                    <div><strong>KR</strong> - South Korea</div>
                    <div><strong>KW</strong> - Kuwait</div>
                    <div><strong>KZ</strong> - Kazakhstan</div>
                    <div><strong>LB</strong> - Lebanon</div>
                    <div><strong>LT</strong> - Lithuania</div>
                    <div><strong>LU</strong> - Luxembourg</div>
                    <div><strong>LV</strong> - Latvia</div>
                    <div><strong>MA</strong> - Morocco</div>
                    <div><strong>MX</strong> - Mexico</div>
                    <div><strong>MY</strong> - Malaysia</div>
                    <div><strong>NG</strong> - Nigeria</div>
                    <div><strong>NL</strong> - Netherlands</div>
                    <div><strong>NO</strong> - Norway</div>
                    <div><strong>NZ</strong> - New Zealand</div>
                    <div><strong>OM</strong> - Oman</div>
                    <div><strong>PE</strong> - Peru</div>
                    <div><strong>PH</strong> - Philippines</div>
                    <div><strong>PK</strong> - Pakistan</div>
                    <div><strong>PL</strong> - Poland</div>
                    <div><strong>PT</strong> - Portugal</div>
                    <div><strong>QA</strong> - Qatar</div>
                    <div><strong>RO</strong> - Romania</div>
                    <div><strong>RS</strong> - Serbia</div>
                    <div><strong>RU</strong> - Russia</div>
                    <div><strong>SA</strong> - Saudi Arabia</div>
                    <div><strong>SE</strong> - Sweden</div>
                    <div><strong>SG</strong> - Singapore</div>
                    <div><strong>SI</strong> - Slovenia</div>
                    <div><strong>SK</strong> - Slovakia</div>
                    <div><strong>TH</strong> - Thailand</div>
                    <div><strong>TN</strong> - Tunisia</div>
                    <div><strong>TR</strong> - Turkey</div>
                    <div><strong>TW</strong> - Taiwan</div>
                    <div><strong>UA</strong> - Ukraine</div>
                    <div><strong>US</strong> - United States</div>
                    <div><strong>UY</strong> - Uruguay</div>
                    <div><strong>VE</strong> - Venezuela</div>
                    <div><strong>VN</strong> - Vietnam</div>
                    <div><strong>ZA</strong> - South Africa</div>
                    <div style="margin-top: 10px;"><strong>*</strong> - All other countries</div>
                    </div>
                </div>
            </div>
        </div>

        <script type="text/javascript">
        jQuery(document).ready(function($) {
            // Tab switching functionality
            $('.nav-tab').on('click', function(e) {
                e.preventDefault();

                // Remove active class from all tabs and content
                $('.nav-tab').removeClass('nav-tab-active');
                $('.ugr-tab-content').removeClass('ugr-tab-active');

                // Add active class to clicked tab
                $(this).addClass('nav-tab-active');

                // Show corresponding content
                var tabId = $(this).attr('href');
                $(tabId).addClass('ugr-tab-active');
            });
            var siteOptions = <?php
                $options_array = [];
                foreach ( $sites as $site ) {
                    $site_url_option = untrailingslashit( get_site_url( $site->blog_id ) );
                    $options_array[] = [
                        'value' => $site_url_option,
                        'text' => $site_url_option
                    ];
                }
                echo json_encode( $options_array );
            ?>;

            $('#ugr-add-rule').on('click', function() {
                var optionsHtml = '<option value="">Select a site...</option>';
                $.each(siteOptions, function(i, opt) {
                    optionsHtml += '<option value="' + opt.value + '">' + opt.text + '</option>';
                });

                var newRow = '<tr>' +
                    '<td><select name="ugr_rules[site][]" class="regular-text" required>' + optionsHtml + '</select></td>' +
                    '<td><input type="text" name="ugr_rules[countries][]" value="" class="regular-text" placeholder="IL,IT,PE or *" required />' +
                    '<p class="description">Use ISO 2-letter country codes (e.g., IL,IT,PE) or * for all countries</p></td>' +
                    '<td><button type="button" class="button ugr-remove-rule">Remove</button></td>' +
                    '</tr>';

                $('#ugr-rules-body').append(newRow);
            });

            $(document).on('click', '.ugr-remove-rule', function() {
                $(this).closest('tr').remove();
            });
        });
        </script>

        <style>
        #ugr-rules-table td {
            vertical-align: top;
            padding: 15px 10px;
        }
        #ugr-rules-table select,
        #ugr-rules-table input[type="text"] {
            width: 100%;
        }
        .description {
            margin-top: 5px;
            font-size: 12px;
        }
        .ugr-instructions-wrapper {
            margin-top: 40px;
        }
        .ugr-instructions-wrapper .nav-tab-wrapper {
            margin-bottom: 0;
            border-bottom: 1px solid #ccd0d4;
        }
        .ugr-tab-content {
            display: none;
            padding: 20px;
            background: #fff;
            border: 1px solid #ccd0d4;
            border-top: none;
        }
        .ugr-tab-content.ugr-tab-active {
            display: block;
        }
        .ugr-tab-content h3 {
            margin-top: 0;
            font-size: 18px;
            color: #2271b1;
        }
        .ugr-tab-content h4 {
            font-size: 15px;
            margin-top: 20px;
            margin-bottom: 10px;
            color: #2271b1;
        }
        .ugr-tab-content code {
            background: #f0f0f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #d63638;
            font-size: 13px;
        }
        .ugr-tab-content pre {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 12px 15px;
            border-radius: 4px;
            overflow-x: auto;
            margin: 10px 0;
        }
        .ugr-tab-content pre code {
            background: transparent;
            color: #d4d4d4;
            padding: 0;
        }
        .ugr-tab-content ul,
        .ugr-tab-content ol {
            margin-left: 20px;
        }
        .ugr-tab-content li {
            margin-bottom: 10px;
        }
        .ugr-tab-content strong {
            color: #2271b1;
        }
        #countries-tab > div > div {
            margin-bottom: 5px;
            font-size: 13px;
        }
        #countries-tab strong {
            color: #0073aa;
            font-family: monospace;
        }
        </style>
        <?php
    }

    /**
     * שומר את ההגדרות של הרשת.
     *
     * @return void
     */
    public function save_network_settings(): void {
        if ( ! current_user_can( 'manage_network_options' ) ) {
            wp_die( 'You do not have permission to perform this action.' );
        }

        check_admin_referer( 'ugr_save_settings_nonce' );

        $redirect_rules = [];

        if ( isset( $_POST['ugr_rules']['site'] ) && isset( $_POST['ugr_rules']['countries'] ) ) {
            $sites = $_POST['ugr_rules']['site'];
            $countries = $_POST['ugr_rules']['countries'];

            for ( $i = 0; $i < count( $sites ); $i++ ) {
                if ( ! empty( $sites[ $i ] ) && ! empty( $countries[ $i ] ) ) {
                    $site_url = esc_url_raw( $sites[ $i ] );
                    $countries_string = sanitize_text_field( $countries[ $i ] );

                    $countries_array = array_map( 'trim', explode( ',', $countries_string ) );

                    foreach ( $countries_array as $country_code ) {
                        if ( $country_code === '*' || preg_match( '/^[A-Z]{2}$/i', $country_code ) ) {
                            $redirect_rules[ strtoupper( $country_code ) ] = $site_url;
                        }
                    }
                }
            }
        }

        update_site_option( 'ugr_redirect_rules', $redirect_rules );

        wp_redirect( add_query_arg(
            [ 'page' => 'user-geo-redirect', 'updated' => 'true' ],
            network_admin_url( 'admin.php' )
        ) );
        exit;
    }
}

// יוזמים את הקלאס כשכל התוספים טעונים
add_action( 'plugins_loaded', function() {
	// Always initialize in Network Admin to show the settings page
	if ( is_multisite() && is_network_admin() ) {
		User_Geo_Redirect::instance();
		return;
	}

	$is_home = false;
	// Get the current full URL
	$current_url = ( ( isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ) ? 'https' : 'http' );
	$current_url .= '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
	// Remove query string and fragment
	$current_url_no_query = strtok($current_url, '?#');
	// Normalize both URLs (remove trailing slashes and www prefix for consistency)
	$current_url_no_query = untrailingslashit($current_url_no_query);
	$current_url_no_query = str_replace('://www.', '://', $current_url_no_query);
	$home_url_normalized  = untrailingslashit( home_url('/') );
	$home_url_normalized  = str_replace('://www.', '://', $home_url_normalized);

	error_log('plugins_loaded - $current_url_no_query:'.$current_url_no_query);
	error_log('plugins_loaded - $home_url_normalized:'.$home_url_normalized);

	if ( $current_url_no_query === $home_url_normalized ) {
		if (
			is_admin() ||
			is_user_logged_in() ||
			wp_doing_ajax() ||
			wp_doing_cron() ||
			(defined('DOING_CRON') && DOING_CRON) ||
			(defined('REST_REQUEST') && REST_REQUEST) ||
			(defined('WP_CLI') && WP_CLI)
		)
		{
			return;
		} else {
			if (GEO_REDIRECT_DEBUG) {
				error_log('plugins_loaded - initializing User_Geo_Redirect');
			}
			User_Geo_Redirect::instance();
		}
	} else {
		error_log('plugins_loaded - not home');
	}
} );

/**
 * Helper function to get user's country name in theme templates
 *
 * @param string $format 'name' for country name (default) or 'code' for country code
 * @return string Country name or code, or empty string if not detected
 */
function ugr_get_user_country( $format = 'name' ): string {
	$instance = User_Geo_Redirect::instance();
	return do_shortcode( '[user_country format="' . esc_attr( $format ) . '"]' );
}
