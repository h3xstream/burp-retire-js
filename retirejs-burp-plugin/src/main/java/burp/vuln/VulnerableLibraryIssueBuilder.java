package burp.vuln;

import burp.*;
import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.vuln.TemplateBuilder;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class VulnerableLibraryIssueBuilder {

    private static final String TITLE = "The JavaScript file '%s' includes a vulnerable version of the library '%s'";
    private static final String TEMPLATE_DESC = "/burp/vuln/description.html";

    public static List<IScanIssue> convert(List<JsLibraryResult> librariesFound, IHttpService httpService, IHttpRequestResponse reqResp, IRequestInfo requestInfo) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        for(JsLibraryResult lib :  librariesFound) {


            //Title summary
            String path = HttpUtil.getPathRequested(requestInfo);
            String filename = HttpUtil.getFileRequested(requestInfo);

            String libraryName = lib.getLibrary().getName();
            String title = String.format(TITLE,filename,libraryName);

            //
            String description = TemplateBuilder.buildDescription(TEMPLATE_DESC,libraryName, lib.getDetectedVersion(), //Library detected
                    lib.getVuln().getInfo(), //List of the URLs
                    lib.getVuln().getAtOrAbove(), lib.getVuln().getBelow()); //Indicator of the affected versions

            issues.add(new VulnerableLibraryIssue(httpService,
                    requestInfo.getUrl(), //URL to map the issue to a request (source of the issue)
                    new MockHttpRequestResponse(reqResp,lib.getRegexRequest(),lib.getRegexResponse()),
                    title, //Title of the issue
                    description, //HTML description
                    mapToBurpSeverity(lib.getVuln().getSeverity()), //Severity .. Could be high, but the risk can never be confirm automatically..
                    "Certain", //The library is old for sure .. if the app is vulnerable, not so sure..

                    libraryName, //The two last info are used to differentiate the vuln.
                    path
                    ));
        }

        Log.debug(issues.size() + " issues raised for the script " + HttpUtil.getPathRequested(requestInfo));
        return issues;
    }

    private static String mapToBurpSeverity(String severity) {
        if(severity.equals("info")) {
            return "Information";
        }
        else if(severity.equals("high") || severity.equals("medium") || severity.equals("low")) {
            //First character to upper for  "High", "Medium", "Low"
            //See : burp.IScanIssue.getSeverity()
            return Character.toUpperCase(severity.charAt(0))+severity.substring(1);
        }
        return "Medium"; //In case the value is invalid, the default will be Medium
    }


}
