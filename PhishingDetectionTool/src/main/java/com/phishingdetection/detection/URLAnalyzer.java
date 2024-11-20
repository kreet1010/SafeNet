package com.phishingdetection.detection;

import com.phishingdetection.utils.HttpUtils;

public class URLAnalyzer {

    public boolean isPhishing(String url) {
    
        if (HttpUtils.isPhishingUrl(url)) {
            return true;
        }
        return false;
    }
}
