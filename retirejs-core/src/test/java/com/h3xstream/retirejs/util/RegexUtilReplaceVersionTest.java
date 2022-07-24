package com.h3xstream.retirejs.util;

import static org.testng.Assert.assertEquals;

import org.testng.annotations.Test;

public class RegexUtilReplaceVersionTest {
    
    @Test
    public void shouldReplaceVersionString() {
        String source = "§§version§§";

        String escaped  = RegexUtil.replaceVersion(source);
        
        assertEquals(escaped, "[0-9][0-9.a-z_\\\\\\\\-]+");
    }
    
    @Test
    public void shouldReplaceNewlines() {
        String source = "/\\*!?[\n *]";

        String escaped  = RegexUtil.replaceVersion(source);
        
        assertEquals(escaped, "/\\*!?[\\n *]");
    }
    
    @Test
    public void shouldReplaceCurlyBracesPairs() {
        String source = "a=t.Backbone={}}";

        String escaped  = RegexUtil.replaceVersion(source);

        assertEquals(escaped, "a=t.Backbone=\\{\\}}");
    }
    
    @Test
    public void shouldReplaceSquareBracesPairs() {
        String source = ";u.settings=[]";

        String escaped  = RegexUtil.replaceVersion(source);

        assertEquals(escaped, ";u.settings=\\[\\]");
    }
}
