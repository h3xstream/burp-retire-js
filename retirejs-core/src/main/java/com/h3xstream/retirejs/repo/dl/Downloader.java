package com.h3xstream.retirejs.repo.dl;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;

public interface Downloader {

    /**
     * @param url URL to request
     * @param file File where the content will be saved.
     * @throws Exception
     */
    void downloadUrlToFile(String url, File file) throws Exception;
}
