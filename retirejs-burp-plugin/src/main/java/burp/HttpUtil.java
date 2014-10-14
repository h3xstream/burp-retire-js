package burp;

public class HttpUtil {


    public static String getContentType(IResponseInfo responseInfo) {
        for (String header : responseInfo.getHeaders()) {
            if (header.startsWith("Content-Type: ")) {
                return header.substring(14);
            }
        }
        return null;
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
}
