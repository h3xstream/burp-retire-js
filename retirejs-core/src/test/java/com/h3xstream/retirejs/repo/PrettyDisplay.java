package com.h3xstream.retirejs.repo;

import java.util.Arrays;
import java.util.List;

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
            System.out.printf("%d. '%s' is under the version '%s' and above '%s'. Therefore, it is vulnerable to %n%s%n",
                    i++,
                    res.getLibrary().getName(),
                    res.getVuln().getBelow(),
                    res.getVuln().getAtOrAbove(),
                    Arrays.toString(res.getVuln().getInfo().toArray()));
        }
        if(results.size() == 0) {
            System.out.println("Nothing found.");
        }

        System.out.println("==================================");
    }
}
