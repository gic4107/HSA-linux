#!/bin/sh

fakeroot make-kpkg -j$1 --initrd kernel_image kernel_headers
