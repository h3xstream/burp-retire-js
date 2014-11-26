package burp.vuln;

import burp.*;
import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.repo.JsLibraryResult;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class VulnerableLibraryIssueBuilder {

    private static final String TITLE = "The JavaScript file '%s' include a vulnerable version of the library '%s'";
    private static final String DESCRIPTION_BEGIN = "The library is vulnerable to the following security issues: <ul>";
    private static final String DESCRIPTION_END = "</ul>\n\nIt is recommend that the library gets updated to the latest version.";
    public static List<IScanIssue> convert(List<JsLibraryResult> librariesFound, IHttpService httpService, IHttpRequestResponse reqResp, IRequestInfo requestInfo) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        for(JsLibraryResult lib :  librariesFound) {

            //Title summary

            String filename = HttpUtil.getFileRequested(requestInfo);

            String libraryName = lib.getLibrary().getName();
            String title = String.format(TITLE,filename,lib.getLibrary().getName());

            //
            StringBuilder description = new StringBuilder(DESCRIPTION_BEGIN);

            for(String refUrl : lib.getVuln().getInfo()) {
                description.append("<li><a href='").append(refUrl).append("'>").append(refUrl).append("</a></li>");
            }
            description.append(DESCRIPTION_END);

            issues.add(new VulnerableLibraryIssue(httpService,
                    requestInfo.getUrl(), //URL to map the issue to a request (source of the issue)
                    reqResp,
                    title, //Title of the issue
                    description.toString(), //HTML description
                    "Medium", //Severity .. Could be high, but the risk can never be confirm automatically..
                    "Certain", //The library is old for sure .. if the app is vulnerable, not so sure..

                    libraryName, //The two last info are used to differentiate the vuln.
                    lib.getVuln().getInfo().get(0)
                    ));
        }

        Log.debug(issues.size() + " issues raised for the script " + HttpUtil.getPathRequested(requestInfo));
        return issues;
    }
}
