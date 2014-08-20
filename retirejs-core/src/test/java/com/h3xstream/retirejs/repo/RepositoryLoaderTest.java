package com.h3xstream.retirejs.repo;


import org.testng.annotations.Test;

import java.io.IOException;

import static org.testng.Assert.assertTrue;

public class RepositoryLoaderTest {

    @Test
    public void testRepositoryLoad() throws IOException {
        RepositoryLoader.syncWithOnlineRepository = false;


        RepositoryLoader loader = new RepositoryLoader();
        Repository localRepoLoad = loader.load();

        assertTrue(localRepoLoad.jsLibrares.size() > 0, "No library was loaded.");
    }
}
