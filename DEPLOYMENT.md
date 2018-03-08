# Burp

Contact : [support@portswigger.net](mailto:support@portswigger.net)

```
Subject: RetireJs plugin updated

Hi,
The plugin RetireJs was updated.

[...] 

The plugin can be recompiled from the source :
https://github.com/h3xstream/burp-retire-js

$ git clone ...
$ mvn clean install -Pburp-only

That's it let me know if you have question.
```

# Maven

Normal build
```
mvn clean install
```

Release
```
mvn versions:set -DnewVersion=3.0.1
mvn clean source:jar javadoc:jar package deploy -P!bigjar,signjars,all-modules
```

 - https://oss.sonatype.org/
 - http://central.sonatype.org/pages/ossrh-guide.html