var csp_header_names = ["content-security-policy", "content-security-policy-report-only", "x-content-security-policy", "x-content-security-policy-report-only"]
var relevant_csp_directives = ["script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem", "style-src-attr", "object-src"]
var report_uri_directive_name = "report-uri"
var report_sample_value = "'report-sample'"


function doesDirectiveExist(tokens, directive) {    
    for(let token of tokens) {
        if(directive === token.trim().split(" ")[0]) {
            return true;
        }
    }
    
    return false;
}

function doesValueExistForDirective(tokens, directive, value) {
    //Assumes the directive exists. Undefined behaviour if it doesn't.
    for(let token of tokens) {
        var tmp = token.trim().split(" ")
        
        if(directive === tmp[0] && tmp.length > 1) {
            var values = tmp.slice(1)
            
            for(let v of values) {
                if(value === v.trim()) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

function doesAnyValueExistForDirective(tokens, directive) {
    //Assumes the directive exists. Undefined behaviour if it doesn't.
    for(let token of tokens) {
        var tmp = token.trim().split(" ")
        
        if(directive === tmp[0] && tmp.length > 1) {
           return true
        }
    }
    
    return false;
}

function amendCSP(tokens, directive, value) {
    //Assumes that value does not exists for directive.
    
    var new_tokens = []
    
    for(let token of tokens) {
        //The array tmp is made by a CSP directive and its values, if they are present.
        var tmp = token.trim().split(" ")
        
        if(directive === tmp[0]) {
            //If we found the directive we were looking for, we insert our value just after the directive identifier...
            tmp[0] = value
            tmp.unshift(directive)

            //...and repack the directive+values string...
            new_tokens.push(tmp.join(" "))
        }
        else {
            //...otherwise, we leave the directive+values string unmodified.
            new_tokens.push(token)
        }
    }
    
    //We return the new CSP tokens (an array of directive+values strings).
    return new_tokens
}

function isCSP(header_name) {
    return csp_header_names.includes(header_name.toLowerCase())
}

function getNewHeader(header) {
    //We ignore non-CSP headers.
    if(isCSP(header["name"])) {
        var csp = header["value"]
        var tokens = csp.split(";")
        
        //If report-uri is not there, or does not include an endpoint, 'report-sample' becomes pointless to inject.
        if(doesDirectiveExist(tokens, report_uri_directive_name) && doesAnyValueExistForDirective(tokens, report_uri_directive_name)) {
            //Technically 'report-sample' for object-src is currently unsupported by all browsers, but I'm including it nonetheless.
            for(let directive of relevant_csp_directives) {
                //We inject 'report-sample' as the first value of <directive> if <directive> is present and does not include 'report-sample'.
                if(doesDirectiveExist(tokens, directive) && !doesValueExistForDirective(tokens, directive, report_sample_value)) {
                    tokens = amendCSP(tokens, directive, report_sample_value);
                }
            }
            
            //We return the new (or unmodified, depending on the contents of the original) CSP header.
            return {"name": header["name"], "value": tokens.join("; ")}
        }
    }
    
    //We return the unmodified non-CSP header.
    return header
}

function edit_headers(e) {
    var headers = []
    
    //Note: multiple CSP headers (also report-only) are supported.
    for(let header of e.responseHeaders) {
        var h = getNewHeader(header)
        
        //We print the new CSP just for debug.
        if(isCSP(h["name"])) {
            console.log("New CSP:")
            console.log(h)
        }
        
        headers.push(h)
    }
    
    return {responseHeaders: headers};
}

browser.webRequest.onHeadersReceived.addListener(
    edit_headers,
    {"urls": [   "*://*/*" ]},
    ["blocking", "responseHeaders"]
)
