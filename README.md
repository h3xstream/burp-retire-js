# Retire.js (Burp plugin) [![Build Status](https://travis-ci.org/h3xstream/burp-retire-js.svg)](https://travis-ci.org/h3xstream/burp-retire-js)

[Burp](http://portswigger.net/burp/)/[ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) extension that integrate [Retire.js](https://github.com/bekk/retire.js) repository to find vulnerable JavaScript libraries. It passively look at JavaScript files loaded and identify those vulnerable based on various signature types (URL, filename, file content or specific hash).

## License

This software is release under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Downloads

Last updated : August 15th, 2017

Burp Suite plugin : [Download](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/releases/burp/burp-retire-js-2.3.0.jar) (also available on the [BApp Store](https://pro.portswigger.net/bappstore/ShowBappDetails.aspx?uuid=36238b534a78494db9bf2d03f112265c))

ZAP plugin : [Download](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/releases/zap/retirejs-alpha-2.3.0.zap)


--------------------------

## Burp plugin

![Retire.js Burp plugin](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/screenshots/screenshot_burp_plugin.png)

![Retire.js Burp plugin](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/screenshots/screenshot_burp_plugin_animate.gif)


## ZAP plugin

![Retire.js ZAP plugin](https://raw.githubusercontent.com/h3xstream/burp-retire-js/gh-pages/screenshots/screenshot_zap_plugin.png)

## Maven plugin [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.h3xstream.retirejs/retirejs-maven-plugin/badge.svg)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.h3xstream.retirejs%22%20a%3A%22retirejs-maven-plugin%22)

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

### Run the Maven plugin as part of your build
Use the following configuration to run the Maven plugin as part of your build.  Only one `<repoUrl>` may be specified at a time.
To scan / iterate earlier in your build cycle, you can bind the plugin to the `validate` phase.
```
  <plugin>    
    <groupId>com.h3xstream.retirejs</groupId>
    <artifactId>retirejs-maven-plugin</artifactId>
    <version>3.0.0</version>
    <configuration>
      <repoUrl>https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json</repoUrl>
      <!--<repoUrl>https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/npmrepository.json</repoUrl>-->
    </configuration>
    <executions>
      <execution>
        <id>scanProjectJavascript</id>
        <goals>
          <goal>scan</goal>
        </goals>
        <phase>install</phase>
      </execution>
    </executions>
  </plugin>
```      
