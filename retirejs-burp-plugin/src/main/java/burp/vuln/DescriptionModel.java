package burp.vuln;

import java.util.ArrayList;
import java.util.List;

public class DescriptionModel {

    private String detectedLibrary;
    private String detectedVersion;

    private final List<String> links = new ArrayList<String>();
    private String aboveVersion;
    private String belowVersion;

    public String getDetectedLibrary() {
        return detectedLibrary;
    }

    public void setDetectedLibrary(String detectedLibrary) {
        this.detectedLibrary = detectedLibrary;
    }

    public String getDetectedVersion() {
        return detectedVersion;
    }

    public void setDetectedVersion(String detectedVersion) {
        this.detectedVersion = detectedVersion;
    }

    public List<String> getLinks() {
        return links;
    }

    public String getAboveVersion() {
        return aboveVersion;
    }

    public void setAboveVersion(String aboveVersion) {
        this.aboveVersion = aboveVersion;
    }

    public String getBelowVersion() {
        return belowVersion;
    }

    public void setBelowVersion(String belowVersion) {
        this.belowVersion = belowVersion;
    }
}
