package com.h3xstream.retirejs.repo;


import org.testng.annotations.Test;

import java.io.IOException;

import static org.testng.Assert.assertTrue;

public class VulnerabilitiesRepositoryLoaderTest {

    @Test
    public void testRepositoryLoad() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;


        VulnerabilitiesRepositoryLoader loader = new VulnerabilitiesRepositoryLoader();
        VulnerabilitiesRepository localRepoLoad = loader.load();

        assertTrue(localRepoLoad.jsLibrares.size() > 0, "No library was loaded.");
    }
}
