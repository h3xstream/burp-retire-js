package com.h3xstream.retirejs.vuln;

import org.testng.annotations.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class TemplateBuilderTest {


    @Test
    public void testTemplateFile() throws IOException {
        List<String> urls = Arrays.asList("http://blog.h3xstream.com","https://csrf.me/");
        String result=TemplateBuilder.buildDescription("/basic_template.txt","yolo.js","1.3.3.7",urls,"1.0.0.0","1.3.3.8");
        System.out.println(result);

        assertTrue(result.contains("yolo.js"), "Missing library name");
        assertTrue(result.contains("1.3.3.7"), "Missing library version");
        assertTrue(result.contains("1.0.0.0"), "Missing library version 'atOrAbove'");
        assertTrue(result.contains("1.3.3.8"), "Missing library version 'below'");
        assertTrue(result.contains("h3xstream.com"), "Missing link #1");
        assertTrue(result.contains("csrf.me"), "Missing link #2");
    }

    @Test
    public void testTemplateNotFound() throws IOException {
        List<String> urls = Arrays.asList("http://blog.h3xstream.com","https://csrf.me/");
        String result=TemplateBuilder.buildDescription("/ouuuuuuups/basic_template.txt","yolo.js","1.3.3.7",urls,"1.0.0.0","1.3.3.8");
        System.out.println(result);

        assertTrue(result.contains("error"),"An error message was expected.");
        assertFalse(result.contains("yolo.js"),"The template should not have been generated.");
    }
}
