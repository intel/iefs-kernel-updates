#!/bin/bash

BUILD_DIR=/tmp/oot-$USER

if [ "$1" = "-d" ]; then
	BUILD_DIR="$2"
	shift 2
fi

gpu=$1

rm -rf "$BUILD_DIR"

mkdir "$BUILD_DIR"

cp -r compat "$BUILD_DIR"
cp -r drivers "$BUILD_DIR"
cp -r files "$BUILD_DIR"
cp -r include *.sh LICENSE modules.* Module.symvers System.map "$BUILD_DIR"

cd "$BUILD_DIR"

ls

if [[ $gpu == "gpu" ]]; then
	export NVIDIA_GPU_DIRECT=${NVIDIA_GPU_DIRECT:-/usr/src/nvidia-450.36.06}
	gpu="-G"
else
	gpu=""
fi

./do-update-makerpm.sh -S ${PWD} -w ${PWD}/tmp $gpu && cd tmp/rpmbuild  && rpmbuild --rebuild --define "_topdir $(pwd)" --nodeps SRPMS/*.src.rpm
