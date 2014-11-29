package burp.vuln;

import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import com.h3xstream.retirejs.vuln.DescriptionModel;
import org.testng.annotations.Test;

import java.io.*;

import static org.testng.Assert.assertTrue;

public class TemplateTester {

    @Test
    public void testTemplateFile() throws IOException {
        String tpl= "/burp/vuln/description.html";
        InputStream in = TemplateTester.class.getResourceAsStream(tpl);

        DescriptionModel model = new DescriptionModel();
        model.setDetectedLibrary("yolo.js");
        model.setDetectedVersion("1.3.3.7");
        model.getLinks().add("http://blog.h3xstream.com");
        model.getLinks().add("https://csrf.me/");

        String result = displayTemplate(in, model);

        System.out.println("<<<<<<<");
        System.out.println(result);
        System.out.println(">>>>>>>");

        assertTrue(result.contains("yolo.js"), "Missing library name");
        assertTrue(result.contains("1.3.3.7"), "Missing library version");

    }

    private String displayTemplate(InputStream tpl, Object model) throws IOException {
        MustacheFactory mf = new DefaultMustacheFactory();
        Mustache mustache = mf.compile(new InputStreamReader(tpl),"");

        ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
        mustache.execute(new PrintWriter(outBuffer),model).flush();
        return outBuffer.toString();
    }
}
