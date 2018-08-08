package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.util.HashUtil;
import org.apache.commons.io.IOUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.List;

import static com.h3xstream.retirejs.repo.PrettyDisplay.displayResults;
import static org.testng.Assert.assertEquals;

public class VulnerabilitiesRepositorySearchByHashTest {

    VulnerabilitiesRepository repo;

    @BeforeClass
    public void setUp() throws IOException {
        Log.DEBUG();

        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = true;

        String filePathTestRepo = getClass().getResource("/retirejs_repository_test.json").toExternalForm();
        repo = new VulnerabilitiesRepositoryLoader().load(filePathTestRepo);
    }

    @Test
    public void findDojoByHash() throws IOException {

        //Hash
//        byte[] scriptBytes = IOUtils.toByteArray(getClass().getResource("/js/dojo-1.4.1.js"));
//        String hash = HashUtil.hashSha1(scriptBytes, 0);
//        System.out.println("Hash computed: "+hash);

        List<JsLibraryResult> res = repo.findByHash("73cdd262799aab850abbe694cd3bfb709ea23627");;
        displayResults(res);
        assertEquals(res.size(), 2, "Dojo 1.4.1 was expected to be found");

    }
}
