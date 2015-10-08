WePay SDK for PHP
=============

WePay's API allows you to easily add payments into your application.

For full documentation, see [WePay's developer documentation](https://www.wepay.com/developer)

Installation
------------

Using [Composer]:
```bash
composer require wepay/php-sdk=^0.2
```

And include it in your scripts:

```php
require_once 'vendor/autoload.php';
```


Usage
-----

In addition to the samples below, we have included a very basic demo application in the `demoapp` directory. See its README file for additional information.

### Configuration ###

For all requests, you must initialize the SDK with your Client ID and Client Secret, into either Staging or Production mode. All API calls made against WePay's staging environment mirror production in functionality, but do not actually move money. This allows you to develop your application and test the checkout experience from the perspective of your users without spending any money on payments.  Our [full documentation](https://www.wepay.com/developer) contains additional information on test account numbers you can use in addition to "magic" amounts you can use to trigger payment failures and reversals (helpful for testing IPNs).

**Note:** Staging and Production are two completely independent environments and share NO data with each other. This means that in order to use staging, you must register at [stage.wepay.com](https://stage.wepay.com/developer) and get a set of API keys for your Staging application, and must do the same on Production when you are ready to go live. API keys and access tokens granted on stage *can not* be used on Production, and vice-versa.

```php
<?php
require_once 'vendor/autoload.php';

// To initialize staging, use WePay::useStaging('ID','SECRET'); instead.
WePay::useProduction('YOUR CLIENT ID', 'YOUR CLIENT SECRET'); 
```

To set an [API-Version](https://www.wepay.com/developer/reference/versioning) in the header with your call request, use:

```php
<?php
require_once 'vendor/autoload.php';

// To initialize staging, use WePay::useStaging('ID','SECRET', 'YOUR API VERSION'); instead.
WePay::useProduction('YOUR CLIENT ID', 'YOUR CLIENT SECRET', 'YOUR API VERSION');
```


### Authentication ###

To obtain an access token for your user, you must redirect the user to WePay for authentication. WePay uses OAuth2 for authorization, which is detailed [in our documentation](https://www.wepay.com/developer/reference/oauth2). To generate the URI to which you must redirect your user, the SDK contains `WePay::getAuthorizationUri($scope, $redirect_uri)`. `$scope` should be an array of scope strings detailed in the documentation. To request full access (most useful for testing, since users may be weary of granting permission to your application if it wants to do too much), you pay pass in `WePay::getAllScopes()`. `$redirect_uri` must be a fully qualified URI where we will send the user after permission is granted (or not granted), and the domain must match your application settings.

If the user grants permission, he or she will be redirected to your `$redirect_uri` with `code=XXXX` appended to the query string. If permission is not granted, we will instead put `error=XXXX` in the query string. If `code` is present, the following will exchange it for an access token. Note that codes are only valid for several minutes, so you should do this immediately after the user is redirected back to your website or application.

```php
if (!empty($_GET['error'])) {
    // User did not grant permissions
} elseif (empty($_GET['code'])) {
    // Set $scope and $redirect_uri before doing this.
    // This will send the user to WePay to authenticate.
    $uri = WePay::getAuthorizationUri($scope, $redirect_uri);
    header("Location: $uri");
    exit;
} else {
    $info = WePay::getToken($_GET['code'], $redirect_uri);
    if ($info) {
        // YOUR ACCESS TOKEN IS HERE
        $access_token = $info->access_token;
    } else {
        // Unable to obtain access token
    }
}
```

Full details on the access token response are [here](https://www.wepay.com/developer/reference/oauth2#token).

**Note:** If you only need access for yourself (e.g., for a personal storefront), the application settings page automatically creates an access token for you. Simply copy and paste it into your code rather than manually going through the authentication flow.

### Making API Calls ###

With the `$access_token` from above, get a new SDK object:

```php
$wepay = new WePay($access_token);
```

Then you can make a simple API call. This will list the user's accounts available to your application:

```php
// (continued from above)
try {
    $accounts = $wepay->request('account/find');

    foreach ($accounts as $account) {
        // Please never blend your views with your business logic like this!
        echo "<a href=\"$account->account_uri\">$account->name</a>: $account->description <br />";
    }
} catch (WePayException $e) {
    // Something went wrong - normally you would log
    // this and give your user a more informative message
    echo $e->getMessage();
}
```

For more details on which API calls are available, their parameters and responses, and which permissions they require,
please see [our documentation](https://www.wepay.com/developer/reference). For some more detailed examples, look in the 
`demoapp` directory and check the README. Dropping the entire directory in a web-accessible location and adding your 
API keys should allow you to be up and running in just a few seconds.

Security
--------

### Connections require TLS 1.2 ###

According to updated PCI requirements, SSL (v2, v3) and early TLS (1.0, 1.1) are no longer considered “strong 
cryptography” and cannot be used as a security control after 2016-06-30. Because of this, WePay will be updating its API 
endpoints to only allow TLS 1.2 connections over the coming months.

WePay SDK for PHP version 0.3.0 is _possibly_ backwards-incompatible depending on how new or old your PHP stack is, 
hence the [Semantic Versioning](http://semver.org) bump.

Using the [PHP cURL extension](https://secure.php.net/manual/en/intro.curl.php), PHP will make outbound requests via the 
system’s cURL installation. For licensing reasons, the PHP cURL extension uses NSS instead of OpenSSL.

* [PHP (Zend Engine) 5.5.19+ or 5.6.3+ is required](https://secure.php.net/manual/en/curl.constants.php).
* The PHP cURL extension requires cURL `7.34.0` (or newer) on the underlying system.
* The PHP cURL extension must be compiled with NSS `3.15.1` (or newer).
* HHVM 3.0 (or newer) and/or Hacklang (any version) has [the same cURL and cURL extension requirements as for 
  PHP](https://twitter.com/SaraMG/status/631654826426798081).


### SSL Certificate ###

If making an API call causes the following problem:

> Uncaught exception 'Exception' with message 'cURL error while making API call to WePay: SSL certificate problem, verify that the CA cert is OK. Details: error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed'

You can read the solution here: https://support.wepay.com/entries/21095813-problem-with-ssl-certificate-verification

  [Composer]: http://getcomposer.org
