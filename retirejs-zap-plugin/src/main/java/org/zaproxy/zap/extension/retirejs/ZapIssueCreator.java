package org.zaproxy.zap.extension.retirejs;

import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.vuln.TemplateBuilder;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;

import java.io.IOException;
import java.util.List;

public class ZapIssueCreator {
    private static Logger logger = Logger.getLogger(ZapIssueCreator.class);

    private static final String TITLE = "The JavaScript file '%s' includes a vulnerable version of the library '%s'";
    private static String TEMPLATE_DESC = "/org/zaproxy/zap/extension/retirejs/description.txt";
    private static String TEMPLATE_OTHER_INFO = "/org/zaproxy/zap/extension/retirejs/other_info.txt";

    public static Alert convertBugToAlert(int pluginId, JsLibraryResult lib, HttpMessage message) {
        String filename = "unknown";
        try {
            filename = getFileRequested(message.getRequestHeader().getURI().getPathQuery());
        }
        catch (IOException e) {
            logger.error(e.getMessage(),e);
        }
        String title = String.format(TITLE,filename,lib.getLibrary().getName());

        String description = TemplateBuilder.buildDescription(TEMPLATE_DESC,
                lib.getLibrary().getName(), //
                lib.getDetectedVersion(), //
                lib.getVuln().getInfo(), //
                lib.getVuln().getAtOrAbove(), //
                lib.getVuln().getBelow());

        String otherInfo = TemplateBuilder.buildDescription(TEMPLATE_OTHER_INFO,
                lib.getLibrary().getName(), //
                lib.getDetectedVersion(), //
                lib.getVuln().getInfo(), //
                lib.getVuln().getAtOrAbove(), //
                lib.getVuln().getBelow());

        Alert alert = new Alert(pluginId, mapToZapSeverity(lib.getVuln().getSeverity()), Alert.SUSPICIOUS, title);
        alert.setDetail(description,
                message.getRequestHeader().getURI().toString(),
                "", //Param
                "", //Attack
                otherInfo, //Other info
                "Update the JavaScript library", //Solution
                joinStrings(lib.getVuln().getInfo()), //Only one link is allow
                message
        );
        return alert;
    }

    private static int mapToZapSeverity(String severity) {
        String severityLower = severity.toLowerCase();
        if(severityLower.equals("high")) {
            return Alert.RISK_HIGH;
        }
        else if (severityLower.equals("medium")) {
            return Alert.RISK_MEDIUM;
        }
        else if (severityLower.equals("low")) {
            return Alert.RISK_LOW;
        }
        else if (severityLower.equals("info")) {
            return Alert.RISK_INFO;
        }

        return Alert.RISK_MEDIUM;
    }

    private static String joinStrings(List<String> info) {
        StringBuilder buffer = new StringBuilder();
        for(String link : info) {
            buffer.append(link).append('\n');
        }
        return buffer.toString();
    }

    public static String getFileRequested(String path) {
        int lastSlash = path.lastIndexOf('/');
        if(lastSlash < 0) lastSlash = 0;
        return path.substring(lastSlash+1);
    }
}
