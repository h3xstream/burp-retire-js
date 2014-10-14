package burp;

import com.h3xstream.retirejs.repo.JsLibraryResult;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class VulnerableLibraryIssueBuilder {

    private static final String TITLE = "The JavaScript file '%s' include a vulnerable version of the library '%s'";
    private static final String DESCRIPTION = "The library '' is vulnerable to the following security issues:";

    public static List<IScanIssue> convert(List<JsLibraryResult> librarliesFound,IHttpService httpService,URL url, IHttpRequestResponse httpMessages) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        for(JsLibraryResult lib :  librarliesFound) {

            //Title summary
            String title = String.format(TITLE,lib.getLibrary().getFilename(),lib.getLibrary().getName());

            //
            String description = DESCRIPTION;

            issues.add(new VulnerableLibraryIssue(httpService,url,httpMessages,
                    title,
                    description,
                    "Medium", //Severity .. Could be high, but the risk can never be confirm automatically..
                    "Tentative"));
        }

        return issues;
    }
}
