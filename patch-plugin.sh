#!/bin/bash

target_base=$1
plugin_base=$2

plugincfg="plugin.cfg"

# Add our plugin to the coredns plugin list
sed -i '/^log:log/a malicious:github.com/giantswarm/coredns-malicious-domain-plugin' "$target_base/$plugincfg"

# Add a replace to coredns's go.mod to use our local plugin
if [ ! -z "$2" ]; then
    echo "Using local plugin path $2"
    echo "replace github.com/giantswarm/coredns-malicious-domain-plugin => $(cd $2 && pwd)" >> "$target_base/go.mod"
fi