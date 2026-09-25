<?php
/**
 * Plugin Name: 光辉ACG防盗链
 * Description: 提供 REST 接口，下发带 HMAC-SHA256 签名的跨子域 Cookie。请修改 wp-config.php define( 'DL_SESSION_SECRET', '密钥字符串' );
 * Version: 1.1
 * Author: GHACG
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class DL_Session_Auth {

    const COOKIE_NAME     = 'dl_session';
    const COOKIE_EXP_NAME = 'dl_session_exp';
    const COOKIE_DOMAIN   = '.ghacg.com';
    const COOKIE_LIFETIME = 3600;
    const REST_NAMESPACE  = 'dl-auth/v1';
    const REST_ROUTE      = '/generate';

    public function __construct() {
        add_action( 'rest_api_init', array( $this, 'register_routes' ) );
        add_action( 'wp_footer', array( $this, 'print_frontend_script' ), 99 );
    }

    public function register_routes() {
        register_rest_route( self::REST_NAMESPACE, self::REST_ROUTE, array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'generate_session_cookie' ),
            'permission_callback' => '__return_true',
        ) );
    }

    /**
     * 读取共享密钥。优先取 wp-config.php 中定义的 DL_SESSION_SECRET 常量，
     * 其次取环境变量，最后回退到占位串（生产请务必覆盖）。
     */
    private function get_secret() {
        if ( defined( 'DL_SESSION_SECRET' ) && DL_SESSION_SECRET !== '' ) {
            return DL_SESSION_SECRET;
        }
        $env = getenv( 'DL_SESSION_SECRET' );
        if ( ! empty( $env ) ) {
            return $env;
        }
        return 'PLEASE_OVERRIDE_DL_SESSION_SECRET';
    }

    public function generate_session_cookie( $request ) {
        $secret    = $this->get_secret();
        $timestamp = time();

        // 仅用 timestamp 参与签名，作为防盗链令牌；不绑定 IP/UID。
        $signature    = hash_hmac( 'sha256', (string) $timestamp, $secret );
        $cookie_value = $timestamp . '|' . $signature;

        $expire = $timestamp + self::COOKIE_LIFETIME;
        $secure = is_ssl();

        // 主 Cookie：HttpOnly，仅供下载子域后端读取并验签
        setcookie( self::COOKIE_NAME, $cookie_value, array(
            'expires'  => $expire,
            'path'     => '/',
            'domain'   => self::COOKIE_DOMAIN,
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ) );

        // 伴随 Cookie：仅存到期时间戳，非 HttpOnly，供前端 JS 判断是否需要刷新
        setcookie( self::COOKIE_EXP_NAME, (string) $expire, array(
            'expires'  => $expire,
            'path'     => '/',
            'domain'   => self::COOKIE_DOMAIN,
            'secure'   => $secure,
            'httponly' => false,
            'samesite' => 'Lax',
        ) );

        return rest_ensure_response( array(
            'success' => true,
            'expires' => $expire,
        ) );
    }

    /**
     * 在前台页面 footer 注入续期脚本。
     * 仅在 dl_session_exp 不存在或临近过期时才会发起一次刷新请求。
     */
    public function print_frontend_script() {
        if ( is_admin() ) {
            return;
        }

        $endpoint = esc_js( rest_url( self::REST_NAMESPACE . self::REST_ROUTE ) );
        $exp_name = esc_js( self::COOKIE_EXP_NAME );
        ?>
<script>
(function () {
    'use strict';
    var ENDPOINT      = '<?php echo $endpoint; ?>';
    var EXP_COOKIE    = '<?php echo $exp_name; ?>';
    var SAFETY_MARGIN = 60;          // 剩余不足 60 秒视为过期，提前续期
    var INFLIGHT_KEY  = 'dl_session_inflight';
    var INFLIGHT_TTL  = 10 * 1000;   // 10 秒内不重复触发

    function readCookie(name) {
        var prefix = name + '=';
        var parts = document.cookie ? document.cookie.split('; ') : [];
        for (var i = 0; i < parts.length; i++) {
            if (parts[i].indexOf(prefix) === 0) {
                return decodeURIComponent(parts[i].substring(prefix.length));
            }
        }
        return null;
    }

    function isCookieValid() {
        var raw = readCookie(EXP_COOKIE);
        if (!raw) return false;
        var exp = parseInt(raw, 10);
        if (!exp || isNaN(exp)) return false;
        var now = Math.floor(Date.now() / 1000);
        return exp - now > SAFETY_MARGIN;
    }

    function isRequestInflight() {
        try {
            var ts = parseInt(sessionStorage.getItem(INFLIGHT_KEY) || '0', 10);
            return ts && (Date.now() - ts < INFLIGHT_TTL);
        } catch (e) {
            return false;
        }
    }

    function markInflight(active) {
        try {
            if (active) {
                sessionStorage.setItem(INFLIGHT_KEY, String(Date.now()));
            } else {
                sessionStorage.removeItem(INFLIGHT_KEY);
            }
        } catch (e) { /* ignore */ }
    }

    function refreshSession() {
        if (isRequestInflight()) return;
        markInflight(true);
        fetch(ENDPOINT, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
            cache: 'no-store',
        }).catch(function () {
            // 静默失败：下载时由后端拒绝，由用户重试即可
        }).then(function () {
            markInflight(false);
        });
    }

    function ensureSession() {
        if (!isCookieValid()) {
            refreshSession();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', ensureSession);
    } else {
        ensureSession();
    }
})();
</script>
        <?php
    }
}

new DL_Session_Auth();
