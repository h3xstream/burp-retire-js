package burp.vuln;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MockHttpRequestResponse implements IHttpRequestResponseWithMarkers {

    IHttpRequestResponse actual;
    List<int[]> requestMarkers = new ArrayList<int[]>();
    List<int[]> responseMarkers = new ArrayList<int[]>();

    MockHttpRequestResponse(IHttpRequestResponse actual, String regexRequest, String regexResponse) {

        if(regexRequest != null) {
            byte[] requestBytes = actual.getRequest();
            addMarkers(requestBytes, requestMarkers, regexRequest);
        }

        if(regexResponse != null) {
            byte[] responseBytes = actual.getResponse();
            addMarkers(responseBytes, responseMarkers, regexResponse);
        }

        this.actual = actual;
    }

    private void addMarkers(byte[] content, List<int[]> markers, String... regexValues) {
        if(regexValues != null)
        for(String value : regexValues) {
            if(value == null) continue;
            int[] position = indexFromRegex(value, content);
            if(position != null) {
                markers.add(position);
            }
        }
    }

    @Override
    public byte[] getRequest() {
        return actual.getRequest();
    }

    @Override
    public void setRequest(byte[] message) {
        actual.setRequest(message);
    }

    @Override
    public byte[] getResponse() {
        return actual.getResponse();
    }

    @Override
    public void setResponse(byte[] message) {
        actual.setResponse(message);
    }

    @Override
    public String getComment() {
        return actual.getComment();
    }

    @Override
    public void setComment(String comment) {
        actual.setComment(comment);
    }

    @Override
    public String getHighlight() {
        return "http";
    }

    @Override
    public void setHighlight(String color) {
        actual.setHighlight(color);
    }

    @Override
    public IHttpService getHttpService() {
        return actual.getHttpService();
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        actual.setHttpService(httpService);
    }

    @Override
    public List<int[]> getRequestMarkers() {
        return requestMarkers;
    }

    @Override
    public List<int[]> getResponseMarkers() {
        return responseMarkers;
    }


    public int[] indexFromRegex(String regex, byte[] content) {
        //NOTE : Regex are not intend to work on byte array. This will work on most JavaScript files except those with Unicode
        Pattern pattern = Pattern.compile(regex);
        Matcher m = pattern.matcher(BurpExtender.getInstance().getHelpers().bytesToString(content));

        while (m.find()) {
            return new int[] {m.start(), m.end()};
        }
        return null;
    }
}
