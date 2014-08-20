package org.zaproxy.zap.extension.retirejs;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

import java.util.ResourceBundle;

public class RetireJsExtension extends ExtensionAdaptor {

    public static final String NAME = RetireJsExtension.class.getName();
    private ResourceBundle messages = null;

    public RetireJsExtension() {
        super(NAME);
        initExtension();
    }

    private void initExtension() {
        messages = ResourceBundle.getBundle(this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
    }

    @Override
    public String getAuthor() {
        return "Philippe Arteau";
    }

    @Override
    public void hook(ExtensionHook extensionHook) {

    }

    @Override
    public void unload() {

    }

}
