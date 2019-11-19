var browser = chrome;
var cspHeaderNames = ["content-security-policy", "content-security-policy-report-only", "x-content-security-policy", "x-content-security-policy-report-only"]
var relevantCSPDirectives = ["script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem", "style-src-attr"]
var reportUriDirectiveName = "report-uri"
var reportSampleValue = "'report-sample'"
var debug = true; //(Version 1.2+) Change this to false for releases.

function doesDirectiveExist(cspTokens, directive) {
    for(let cspToken of cspTokens) {
        if(directive === cspToken.trim().split(" ")[0]) {
            return true;
        }
    }
    
    return false;
}

function doesValueExistForDirective(cspTokens, directive, value) {
    //Assumes the directive exists. Undefined behaviour if it doesn't.
    for(let cspToken of cspTokens) {
        let cspTokenTokens = cspToken.trim().split(" ");
        
        if(directive === cspTokenTokens[0] && cspTokenTokens.length > 1) {
            let values = cspTokenTokens.slice(1);
            
            for(let v of values) {
                if(value === v.trim()) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

function doesAnyValueExistForDirective(cspTokens, directive) {
    //Assumes the directive exists. Undefined behaviour if it doesn't.
    for(let cspToken of cspTokens) {
        let cspTokenTokens = cspToken.trim().split(" ");
        
        //[<directive>, <value1>, ..., <valueN>]
        //Also, a value is meaningful if it is made by something else than mere spaces and similar.
        if(directive === cspTokenTokens[0]) {
            return cspTokenTokens.length > 1 && cspTokenTokens[1].trim().length > 0;
        }
    }
    
    return false;
}

function amendCSP(cspTokens, directive, value) {
    //Assumes that value does not exists for directive.
    
    let newCSPTokens = [];
    
    for(let cspToken of cspTokens) {
        //The array tmp is made by a CSP directive and its values, if they are present.
        let cspTokenTokens = cspToken.trim().split(" ")
        
        if(directive === cspTokenTokens[0]) {
            //If we found the directive we were looking for, we insert our value just after the directive identifier...
            cspTokenTokens[0] = value;
            cspTokenTokens.unshift(directive);

            //...and repack the directive+values string...
            newCSPTokens.push(cspTokenTokens.join(" "));
        }
        else {
            //...otherwise, we leave the directive+values string unmodified.
            newCSPTokens.push(cspToken);
        }
    }
    
    //We return the new CSP tokens (an array of directive+values strings).
    return newCSPTokens;
}

function isCSP(headerName) {
    return cspHeaderNames.includes(headerName.toLowerCase());
}

function getNewHeader(header) {
    //We ignore non-CSP headers.
    if(isCSP(header["name"])) {
        let csp = header["value"];
        let cspTokens = csp.split(";");
        
        //If report-uri is not there, or does not include an endpoint, 'report-sample' becomes pointless to inject.
        if(doesDirectiveExist(cspTokens, reportUriDirectiveName) && doesAnyValueExistForDirective(cspTokens, reportUriDirectiveName)) {
            //Technically 'report-sample' for object-src is currently unsupported by all browsers, but I'm including it nonetheless.
            for(let directive of relevantCSPDirectives) {
                //We inject 'report-sample' as the first value of <directive> if <directive> is present and does not include 'report-sample'.
                if(doesDirectiveExist(cspTokens, directive) && !doesValueExistForDirective(cspTokens, directive, reportSampleValue)) {
                    cspTokens = amendCSP(cspTokens, directive, reportSampleValue);
                }
            }
            
            //We return the new (or unmodified, depending on the contents of the original) CSP header.
            return {name: header["name"], value: cspTokens.join("; ")};
        }
    }
    
    //We return the unmodified non-CSP header.
    return header;
}

function editHeaders(e) {
    let headers = [];
    
    //Note: multiple CSP headers (also report-only) are supported.
    for(let header of e.responseHeaders) {
        let h = getNewHeader(header);
        
        //We print the CSP header just for debug, but only if it exists and modifications have been performed on it.
        if(debug && isCSP(h["name"]) && h["value"] !== header["value"]) {
            console.log("New CSP:");
            console.log(h);
        }
        
        headers.push(h);
    }
    
    return {responseHeaders: headers};
}

browser.webRequest.onHeadersReceived.addListener(
    editHeaders,
    {"urls": [   "*://*/*" ]},
    ["blocking", "responseHeaders"]
);

function checkHeaders(e) {
    for(let header of e.responseHeaders) {
        if(isCSP(header["name"])) {
            console.log("To double check:");
            console.log(header);
        }
    }

    return e;
}

if(debug) {
    browser.webRequest.onResponseStarted.addListener(
        checkHeaders,
        {"urls": ["*://*/*"]},
        ["responseHeaders"]
    );
}