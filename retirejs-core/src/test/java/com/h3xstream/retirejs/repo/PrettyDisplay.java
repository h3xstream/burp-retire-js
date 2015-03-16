package com.h3xstream.retirejs.repo;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class PrettyDisplay {

    /**
     * Display the result of a scan to the command line.
     * Used by tests including "VulnerabilitiesRepositorySearch***"
     * @param results
     */
    public static void displayResults(List<JsLibraryResult> results) {
        System.out.println("==================================");
        System.out.println("Results:");
        int i=0;
        for(JsLibraryResult res : results) {
            System.out.printf("%d. '%s' is under the version '%s' and above '%s'. " +
                            "Therefore, it is vulnerable to :%n%s%n" +
                            "Identifiers: %s%n" +
                            "Severity: %s%n",
                    i++,
                    res.getLibrary().getName(),
                    res.getVuln().getBelow(),
                    res.getVuln().getAtOrAbove(),
                    Arrays.toString(res.getVuln().getInfo().toArray()),
                    mapToString(res.getVuln().getIdentifiers()),
                    res.getVuln().getSeverity()
                    );
        }
        if(results.size() == 0) {
            System.out.println("Nothing found.");
        }

        System.out.println("==================================");
    }

    private static String mapToString(Map<String, List<String>> identifiers) {
        StringBuilder buffer = new StringBuilder();
        for(Map.Entry<String,List<String>> e : identifiers.entrySet()) {
            buffer.append(e.getKey()).append(": \'") //
                    .append(Arrays.toString(e.getValue().toArray())) //
                    .append("\'");
        }
        return buffer.toString();
    }
}
