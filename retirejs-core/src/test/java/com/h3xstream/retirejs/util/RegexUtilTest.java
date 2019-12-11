package com.h3xstream.retirejs.util;

import org.apache.commons.io.IOUtils;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.regex.Pattern;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

public class RegexUtilTest {
    @Test
    public void testSimpleRegex() {
        Pattern pattern1 = Pattern.compile("simplelib_([\\d]\\.[\\d]\\.[\\d]).js");

        String valueExtract = RegexUtil.simpleMatch(pattern1, "simplelib_1.2.3.js");

        assertEquals(valueExtract,"1.2.3");
    }

    @Test
    public void testUnexpectedRegex() {
        //Regex with missing group
        Pattern pattern1 = Pattern.compile("simplelib_[\\d]\\.[\\d]\\.[\\d].js");

        try {
            String valueExtract = RegexUtil.simpleMatch(pattern1, "simplelib_1.2.3.js");
            fail("The regex passed is invalid. A group should be specify.");
        }
        catch(IllegalArgumentException e) {
            System.out.println("As expected");
        }
    }

    @Test
    public void testReplaceMatchFound() {
        //Ref: http://ajax.googleapis.com/ajax/libs/dojo/1.10.1/dojo/dojo.js
        String dojoContent = ";dojo.version={major:1,minor:10,patch:1,flag:\"\",";
        String dojoRegex = "/dojo.version=\\{major:([0-9]+),minor:([0-9]+),patch:([0-9]+)/$1.$2.$3/";

        String extractedVersion = RegexUtil.replaceMatch(dojoRegex,dojoContent);
        System.out.println(extractedVersion);

        assertEquals(extractedVersion, "1.10.1");
    }

    @Test
    public void testReplaceMatchNotFound() {
        String dojoContent = ";dojo.version={major:1,m1N0r:10,patch:1,flag:\"\"";
        String dojoRegex = "/dojo.version=\\{major:([0-9]+),minor:([0-9]+),patch:([0-9]+)/$1.$2.$3/";

        String extractedVersion = RegexUtil.replaceMatch(dojoRegex,dojoContent);

        assertNull(extractedVersion);
    }

    /**
     * This test make sure the bug #54 is fixed.
     */
    @Test
    public void testRegexStackOverflow() throws IOException {
        Pattern p = Pattern.compile("/\\*!?[\\n *]+jQuery UI ([0-9][0-9.a-z_\\\\\\\\-]+)(.*\\n)*.*\\.ui\\.dialog");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        IOUtils.copy(this.getClass().getResourceAsStream("/js/jquery-ui-1.6rc6-customized.js"),out);
        assertNull(RegexUtil.simpleMatch(p,new String(out.toByteArray(),"UTF-8")));
    }
}
