#Retire.js (Burp plugin) [![Build Status](https://travis-ci.org/h3xstream/burp-retire-js.png)](https://travis-ci.org/h3xstream/burp-retire-js)

[Burp](http://portswigger.net/burp/)/[ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) extension that integrate [Retire.js](https://github.com/bekk/retire.js) repository to find vulnerable JavaScript libraries. It passively look at JavaScript files loaded and identify those vulnerable based on various signature types (URL, filename, file content or specific hash).

## License

This software is release under [LGPL](http://www.gnu.org/licenses/lgpl.html).

## Downloads

Burp Suite plugin : [Download](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/releases/burp/burp-retire-js-1.jar)

ZAP plugin : [Download](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/releases/zap/retirejs-alpha-1.zap)

## Screenshots

### Burp:

![Retire.js Burp plugin](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/screenshots/screenshot_burp_plugin.png)

### ZAP

![Retire.js ZAP plugin](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/screenshots/screenshot_zap_plugin.png)

### Maven [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.h3xstream.retirejs/retirejs-maven-plugin/badge.svg)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.h3xstream.retirejs%22%20a%3A%22retirejs-maven-plugin%22)

Run the Maven plugin with the goal `scan`:

    $ cd myproject
    $ mvn com.h3xstream.retirejs:retirejs-maven-plugin:scan
       [...]
    [INFO] --- retirejs-maven-plugin:1.0.0-SNAPSHOT:scan (default-cli) @ myproject ---
    [WARNING] jquery.js contains a vulnerable JavaScript library.
    [INFO] Path: C:\Code\myproject\src\main\webapp\js\jquery.js
    [INFO] jquery version 1.8.1 is vulnerable.
    [INFO] + http://bugs.jquery.com/ticket/11290
    [INFO] + http://research.insecurelabs.org/jquery/test/
       [...]

The additional parameter `-DretireJsBreakOnFailure` can be use to break the build when at least one vulnerability is found.

    [INFO] ------------------------------------------------------------------------
    [INFO] BUILD FAILURE
    [INFO] ------------------------------------------------------------------------
    [INFO] Total time: 1.450 s
    [INFO] Finished at: 2015-02-19T13:37:00-05:00
    [INFO] Final Memory: 11M/245M
    [INFO] ------------------------------------------------------------------------
    [ERROR] Failed to execute goal com.h3xstream.retirejs:retirejs-maven-plugin:1.0.0:scan (default-cli) on project
    my-web-app: 6 known vulnerabilities were identified in the JavaScript librairies. -> [Help 1]
    [ERROR]
