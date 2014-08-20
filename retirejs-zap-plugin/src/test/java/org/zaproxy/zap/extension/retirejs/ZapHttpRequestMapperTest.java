//package org.zaproxy.zap.extension.scriptgen;
//
//import org.parosproxy.paros.network.HttpMessage;
//import org.parosproxy.paros.network.HttpRequestHeader;
//import org.testng.annotations.BeforeClass;
//import org.testng.annotations.Test;
//
//import java.io.IOException;
//
//import static org.mockito.Mockito.mock;
//import static org.mockito.Mockito.when;
//
//public class ZapHttpRequestMapperTest {
//
//    HttpMessage msg;
//
//    @BeforeClass
//    public void beforeClass() {
//
//        HttpMessage msg = mock(HttpMessage.class);
//        HttpRequestHeader reqHeader = mock(HttpRequestHeader.class);
//        when(msg.getRequestHeader()).thenReturn(reqHeader);
//    }
//
//    //public static void main(String[] args) {
//    @Test
//    public void transformRequest() throws IOException {
//
//
//
//        ZapHttpRequestMapper.buildRequestInfo(msg);
//    }
//}
