package burp;

import com.h3xstream.retirejs.repo.dl.Downloader;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.net.URL;

public class BurpUpstreamDownloader implements Downloader {

    private final IBurpExtenderCallbacks callbacks;
    public BurpUpstreamDownloader(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    /**
     * This implementation use the upstream proxy from Burp with <code>callbacks.makeHttpRequest()</code>
     * (Ref: http://blog.portswigger.net/2018/01/your-recipe-for-bapp-store-success.html)
     *
     * @param url
     * @param file
     * @throws Exception
     */
    @Override
    public void downloadUrlToFile(String url, File file) throws Exception {
        URL urlQuery = new URL(url);

        IExtensionHelpers helpers = callbacks.getHelpers();

        byte[] request = helpers.buildHttpRequest(urlQuery);
        int port = urlQuery.getPort() != -1 ? urlQuery.getPort() : (urlQuery.getProtocol().equals("https") ? 443 : 80);
        IHttpService service = helpers.buildHttpService(urlQuery.getHost(), port, urlQuery.getProtocol());
        IHttpRequestResponse resp = callbacks.makeHttpRequest(service, request);

        IResponseInfo respInfo = helpers.analyzeResponse(resp.getResponse());
        String content = new String(resp.getResponse(),respInfo.getBodyOffset(),resp.getResponse().length-respInfo.getBodyOffset());

        try(PrintWriter writer = new PrintWriter(new FileOutputStream(file))) {
            writer.print(content);
            writer.flush();
        }

    }
}
