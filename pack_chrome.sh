#!/bin/bash

echo "Packing the addon for Chrome..."
cd chrome
zip -r -FS ../report-sample-chrome.zip *
echo