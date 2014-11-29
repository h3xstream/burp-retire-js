package com.h3xstream.retirejs.vuln;

import com.esotericsoftware.minlog.Log;
import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;

import java.io.*;
import java.util.List;

public class TemplateBuilder {

    public static String buildDescription(String templateFile, String detectedLibrary,String detectedVersion,List<String> urls,String aboveVersion,String belowVersion) {
        InputStream tpl = TemplateBuilder.class.getResourceAsStream(templateFile);

        try {
            //Build the model mapped to the template
            DescriptionModel model = new DescriptionModel();
            model.setDetectedLibrary(detectedLibrary);
            model.setDetectedVersion(detectedVersion);
            model.getLinks().addAll(urls);
            model.setAboveVersion(aboveVersion == null || "".equals(aboveVersion) ? "*" : aboveVersion);
            model.setBelowVersion(belowVersion);

            //Compile the template
            MustacheFactory mf = new DefaultMustacheFactory();
            Mustache mustache = mf.compile(new InputStreamReader(tpl), "");

            //OutputStream to String
            ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
            mustache.execute(new PrintWriter(outBuffer), model).flush();
            return outBuffer.toString();
        } catch (IOException e) {
            Log.error("Unable to generate the description." + e.getMessage());
            return "An error occurs while loading description template.";
        }
    }
}
