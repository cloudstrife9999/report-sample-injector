#!/bin/bash

echo "Packing the addon for Firefox..."
cd firefox
zip -r -FS ../report-sample-firefox.zip *
echo