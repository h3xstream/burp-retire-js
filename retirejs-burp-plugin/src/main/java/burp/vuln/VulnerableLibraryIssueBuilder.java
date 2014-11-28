package burp.vuln;

import burp.*;
import com.esotericsoftware.minlog.Log;
import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import com.h3xstream.retirejs.repo.JsLibraryResult;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class VulnerableLibraryIssueBuilder {

    private static final String TITLE = "The JavaScript file '%s' include a vulnerable version of the library '%s'";
    public static List<IScanIssue> convert(List<JsLibraryResult> librariesFound, IHttpService httpService, IHttpRequestResponse reqResp, IRequestInfo requestInfo) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        for(JsLibraryResult lib :  librariesFound) {


            //Title summary
            String path = HttpUtil.getPathRequested(requestInfo);
            String filename = HttpUtil.getFileRequested(requestInfo);

            String libraryName = lib.getLibrary().getName();
            String title = String.format(TITLE,filename,libraryName);

            //
            String description = buildDescription(libraryName, lib.getDetectedVersion(), //Library detected
                    lib.getVuln().getInfo(), //List of the URLs
                    lib.getVuln().getAtOrAbove(), lib.getVuln().getBelow()); //Indicator of the affected versions

            issues.add(new VulnerableLibraryIssue(httpService,
                    requestInfo.getUrl(), //URL to map the issue to a request (source of the issue)
                    reqResp,
                    title, //Title of the issue
                    description, //HTML description
                    "Medium", //Severity .. Could be high, but the risk can never be confirm automatically..
                    "Certain", //The library is old for sure .. if the app is vulnerable, not so sure..

                    libraryName, //The two last info are used to differentiate the vuln.
                    path
                    ));
        }

        Log.debug(issues.size() + " issues raised for the script " + HttpUtil.getPathRequested(requestInfo));
        return issues;
    }

    private static String buildDescription(String detectedLibrary,String detectedVersion,List<String> urls,String aboveVersion,String belowVersion) {
        InputStream tpl = VulnerableLibraryIssueBuilder.class.getResourceAsStream("/burp/vuln/description.html");

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
            Log.error("Unable to generate the HTML description."+e.getMessage());
            return "<b>An error occurs while loading description template.</b>";
        }
    }
}
