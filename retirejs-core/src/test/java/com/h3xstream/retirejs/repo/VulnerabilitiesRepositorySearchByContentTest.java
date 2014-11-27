package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import org.apache.commons.io.IOUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.List;

import static com.h3xstream.retirejs.repo.PrettyDisplay.displayResults;
import static org.testng.Assert.assertEquals;

public class VulnerabilitiesRepositorySearchByContentTest {

    @BeforeClass
    public void setUp() {
        Log.DEBUG();
    }

    @Test
    public void findJqueryByFilename() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        VulnerabilitiesRepository repo = new VulnerabilitiesRepositoryLoader().load();


        String scriptJquery = IOUtils.toString(getClass().getResource("/js/jquery-1.6.2.js"));

        List<JsLibraryResult> res = repo.findByFileContent(scriptJquery);
        displayResults(res);
        assertEquals(res.size(), 2, "Jquery not found (file:/js/jquery-1.6.2.js)");


    }

    @Test
    public void findByFilenameNoFalsePositive() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        VulnerabilitiesRepository repo = new VulnerabilitiesRepositoryLoader().load();


        String scriptAngularJs = IOUtils.toString(getClass().getResource("/js/angular.safe.js"));
        List<JsLibraryResult> res = repo.findByFileContent(scriptAngularJs);
        displayResults(res);
        assertEquals(res.size(), 0, "No signature are expect to trigger..");
    }
}
