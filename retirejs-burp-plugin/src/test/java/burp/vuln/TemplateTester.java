package burp.vuln;

import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import com.h3xstream.retirejs.vuln.DescriptionModel;
import com.h3xstream.retirejs.vuln.TemplateBuilder;
import org.testng.annotations.Test;

import java.io.*;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertTrue;

public class TemplateTester {

    @Test
    public void testTemplateFile() throws IOException {
        List<String> urls = Arrays.asList("http://blog.h3xstream.com", "https://csrf.me/");
        String result= TemplateBuilder.buildDescription("/burp/vuln/description.html", "yolo.js", "1.3.3.7", urls, "1.0.0.0", "1.3.3.8");
        System.out.println(result);

        assertTrue(result.contains("yolo.js"), "Missing library name");
        assertTrue(result.contains("1.3.3.7"), "Missing library version");

    }
}
