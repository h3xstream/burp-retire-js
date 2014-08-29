package com.h3xstream.retirejs.util;

import org.testng.annotations.Test;

import java.util.regex.Pattern;

import static org.testng.Assert.assertEquals;
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

}
