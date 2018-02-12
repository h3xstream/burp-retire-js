package burp;


public class HttpUtil {

    /**
     *
     * @param responseInfo
     * @return
     */
    public static String getContentType(IResponseInfo responseInfo) {
        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith("content-type: ")) {
                return header.substring(14);
            }
        }
        return "";
    }


    /**
     * Extract the path from the first header.
     *
     * Input expected :
     * - GET /index.html HTTP/1.1
     * - POST /index.html HTTP/1.1
     *
     * @param request
     * @return
     */
    public static String getPathRequested(IRequestInfo request) {
        String h = request.getHeaders().get(0);
        return h.substring(h.indexOf(" ") + 1, h.lastIndexOf(" "));
    }

    public static String getFileRequested(IRequestInfo request) {
        String path = getPathRequested(request);
        int lastSlash = path.lastIndexOf('/');
        if(lastSlash < 0) lastSlash = 0;
        return path.substring(lastSlash+1);
    }
}
