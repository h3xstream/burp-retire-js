package com.h3xstream.retirejs.repo;

import java.util.ArrayList;
import java.util.List;

public class Repository {

    List<JsLibrary> jsLibrares = new ArrayList<JsLibrary>();

    public void addLibrary(JsLibrary lib) {
        jsLibrares.add(lib);
    }

}
