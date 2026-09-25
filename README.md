# wp-ghacg-dl

与 ghacg-dl 网关协同工作的Wordpress插件，下发HMAC签名。

要使其工作，请修改 Wordpress 根目录下的 `wp-config.php`，追加一行：

```
wp-config.php define( 'DL_SESSION_SECRET', '密钥字符串' );
```

请使用随机ASCII字符串作为密钥字符串。
