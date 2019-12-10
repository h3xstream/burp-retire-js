package com.h3xstream.retirejs.repo.dl;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;

public interface Downloader {

    /**
     * Download the content at the URL given and save it locally.
     * This interface is used to switch between HTTP connector.
     *
     * In the context of Maven, the connection need to pass through Maven API in order
     * to benefit from its proxy configuration. The Maven plugin would otherwise not work on enterprise network.
     *
     * @param url URL to request
     * @param file File where the content will be saved.
     * @throws Exception Connection error most likely
     */
    void downloadUrlToFile(String url, File file) throws Exception;
}
