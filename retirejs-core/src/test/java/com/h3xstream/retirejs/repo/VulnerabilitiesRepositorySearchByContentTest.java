package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import org.apache.commons.io.IOUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.List;

import static com.h3xstream.retirejs.repo.PrettyDisplay.displayResults;
import org.json.JSONException;
import static org.testng.Assert.assertEquals;

public class VulnerabilitiesRepositorySearchByContentTest {
    VulnerabilitiesRepository repo;

    @BeforeClass
    public void setUp() throws IOException, JSONException {
        Log.DEBUG();

        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = true;
        String filePathTestRepo = getClass().getResource("/retirejs_repository_test.json").toExternalForm();
        repo = new VulnerabilitiesRepositoryLoader().load(filePathTestRepo);
    }

    @Test
    public void findJqueryByContent() throws IOException {


        String scriptJquery = IOUtils.toString(getClass().getResource("/js/jquery-1.6.2.js"));

        List<JsLibraryResult> res = repo.findByFileContent(scriptJquery);
        displayResults(res);
        assertEquals(res.size(), 2, "Jquery not found (file:/js/jquery-1.6.2.js)");


    }

    @Test
    public void findByContentNoFalsePositive() throws IOException {

        String scriptAngularJs = IOUtils.toString(getClass().getResource("/js/angular.safe.js"));
        List<JsLibraryResult> res = repo.findByFileContent(scriptAngularJs);
        displayResults(res);
        assertEquals(res.size(), 0, "No signature are expect to trigger..");
    }
}
