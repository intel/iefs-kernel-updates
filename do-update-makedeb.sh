#!/bin/bash

export DEFAULT_KERNEL_VERSION=$(uname -r)
kerneldir="./"

modules_cnt=0

# Add each module separately
modules[$modules_cnt]="rv"
files_to_copy[$modules_cnt]="
	drivers/infiniband/ulp/rv/rv_main.c
	drivers/infiniband/ulp/rv/rv_file.c
	drivers/infiniband/ulp/rv/rv_mr.c
	drivers/infiniband/ulp/rv/rv_rdma.c
	drivers/infiniband/ulp/rv/rv_conn.c
	drivers/infiniband/ulp/rv/rv.h
	drivers/infiniband/ulp/rv/rv_mr_cache.c
	drivers/infiniband/ulp/rv/rv_mr_cache.h
	drivers/infiniband/ulp/rv/trace.c
	drivers/infiniband/ulp/rv/trace.h
	drivers/infiniband/ulp/rv/trace_mr_cache.h
	drivers/infiniband/ulp/rv/trace_conn.h
	drivers/infiniband/ulp/rv/trace_dev.h
	drivers/infiniband/ulp/rv/trace_mr.h
	drivers/infiniband/ulp/rv/trace_user.h
	drivers/infiniband/ulp/rv/trace_rdma.h
	include/uapi/rdma/rv_user_ioctls.h
	"

# Add each module separately
include_dirs[0]="include/uapi/rdma"
include_files_to_copy[0]="
	include/uapi/rdma/rv_user_ioctls.h
"
include_dirs[1]="compat/"
include_files_to_copy[1]=""

include_dirs_cnt=${#include_dirs[@]}

# ridiculously long to encourage good names later
debname="iefs-kernel-updates"

set -e

if [[ -e /etc/os-release ]]; then
	. /etc/os-release
else
	echo "File /etc/os-release is missing."
	exit 1
fi
VERSION_ID_MAJOR=${VERSION_ID%%.*}
VERSION_ID_MINOR=${VERSION_ID#*.}
if [[ $VERSION_ID_MINOR == $VERSION_ID ]]; then
	VERSION_ID_MINOR=''
fi

echo "VERSION_ID = $VERSION_ID"
echo "PRETTY_NAME = $PRETTY_NAME"
if [[ -n "$MVERSION" ]]; then
	echo "MVERSION = $MVERSION"
fi

function usage
{
	cat <<EOL
usage:
	${0##*/} -h
	${0##*/} [-G] [-w dirname]
	${0##*/} -S srcdir [-w dirname]

Options:

-G         - Enable building a GPU Direct package
-S srcdir  - fetch source directly from a specified directory

-w dirname - work directory, defaults to a mktemp directory
-h         - this help text
EOL
}

gpubuild="false"
srcdir=""
workdir=""
filedir=""
ifs_distro=""
distro=""
distro_dir=""
compat_dir=""
# Make sure to update this variable when a new distro is added
while getopts ":GS:hw:" opt; do
    	case "$opt" in
	G)	gpubuild="true"
		;;
	S)	srcdir="$OPTARG"
		[ ! -e "$srcdir" ] && echo "srcdir $srcdir not found" && exit 1
		srcdir=$(readlink -f "$srcdir")
		;;
	h)	usage
		exit 0
		;;
	w)	workdir="$OPTARG"
		;;

    	esac
done

compat_dir=UB$VERSION_ID_MAJOR$VERSION_ID_MINOR
if [[ ! -d $PWD/compat/$compat_dir ]]; then
	echo "compat directory $compat_dir is missing, cannot build"
	exit
fi

if [ $gpubuild = 'true' ]; then
	echo "GPU Direct enabled build"
fi

# create final version of the variables
if [ -n "$workdir" ]; then
	mkdir -p "$workdir" || exit 1
else
	workdir=$(mktemp -d --tmpdir=$(pwd) build.XXXX)
	[ ! $? ] && exit 1
fi

ifs_distro="IFS_$compat_dir"
distro=$ID

echo "ifs_distro = $ifs_distro"
echo "compat_dir = $compat_dir"
echo "distro = $distro"

files_to_copy[0]+="
	compat/$compat_dir/compat.c
	compat/common/compat_common.c
	"

include_files_to_copy[1]="
	compat/$compat_dir/compat.h
	compat/common/compat_common.h
	"

if [ $gpubuild = 'true' ]; then
	files_to_copy[0]+="
		drivers/infiniband/ulp/rv/gpu.h
		drivers/infiniband/ulp/rv/gdr_ops.c
		drivers/infiniband/ulp/rv/gdr_ops.h
		drivers/infiniband/ulp/rv/trace_gpu.h
	"
fi

# configure the file dir
filedir=$srcdir/files

# after cd, where are we *really*
cd -P "$workdir"; workdir=$(pwd)
tardir=$workdir/stage
rm -rf $tardir
for (( i = 0 ; i <= modules_cnt ; i++ ))
do
	mkdir -p $tardir/${modules[$i]}
done

echo "Working in $workdir"

echo "NVIDIA env var: $NVIDIA_GPU_DIRECT"

# create the Makefiles
echo "Creating Makefile ($tardir/Makefile)"

if [ $gpubuild = 'true' ]; then
cp $filedir/Makefile.top.gpu $tardir/Makefile
else
cp $filedir/Makefile.top $tardir/Makefile
fi

sed -i "s/IFS_DISTRO/$ifs_distro/g" $tardir/Makefile

echo "Creating Makefile ($tardir/rv/Makefile)"
if [ $gpubuild = 'true' ]; then
	cp $filedir/Makefile.rv.gpu $tardir/rv/Makefile
else
	cp $filedir/Makefile.rv $tardir/rv/Makefile
fi

if [[ ! -s $srcdir/compat/$compat_dir/compat.c ]]; then
	sed -i "s/compat.o//g" $tardir/rv/Makefile
fi

if [ "$DEFAULT_KERNEL_VERSION" == "" ]; then
	echo "Unable to generate the kernel version"
	exit 1
fi

if echo $srcdir | grep -q "components";  then
	debrelease=$(git rev-list WFR_driver_first..HEAD -- $srcdir | wc -l)
	echo "ifs-all build"
else
	debrelease=$(cd "$srcdir"; git rev-list "WFR_driver_first..HEAD" | wc -l)
	echo "wfr-linux-devel build"
fi
debrelease=$((debrelease + 5000))
if [ $gpubuild = 'true' ]; then
	debrelease+="cuda"
fi
echo "debrelease = $debrelease"
export debrelease

echo "Setting up DEB build area"
mkdir -p debbuild

# make sure deb component strings are clean, should be no-ops
debname=$(echo "$debname" | sed -e 's/[.]/_/g')
debversion=$(echo "$DEFAULT_KERNEL_VERSION" | sed -e 's/_generic//')
debrequires=$(echo "$DEFAULT_KERNEL_VERSION" | sed -e 's/.[^.]*$//')

# get kernel(-devel) deb version and release values
kernel_debver=$(uname -r)
kmod_subdir=extra

# create a new $debname.conf and $debname.files
src_path=$workdir/debbuild

# prepare files list and depmod config for every module built
cat > $src_path/dkms.conf << EOF
MAKE="make -C \${kernel_source_dir} MVERSION=${MVERSION} CONFIG_INFINIBAND_RV=m M=\${dkms_tree}/${debname}/${debrelease}/build"
CLEAN="make clean"
PACKAGE_NAME="${debname}"
PACKAGE_VERSION="${debrelease}"
AUTOINSTALL="yes"
EOF

modlist=""
for (( i = 0 ; i <= modules_cnt ; i++ ))
do
        echo "override ${modules[$i]} $kernel_debver-* weak-updates/${modules[$i]}" >> $src_path/$debname.conf
        echo "/lib/modules/%2-%1/$kmod_subdir/$debname/${modules[$i]}.ko" >> $src_path/$debname.files
        echo "BUILT_MODULE_NAME[$i]='${modules[$i]}'" >> $src_path/dkms.conf
        echo "BUILT_MODULE_LOCATION[$i]='${modules[$i]}/'" >> $src_path/dkms.conf
        echo "DEST_MODULE_LOCATION[$i]='/$kmod_subdir/$debname'" >> $src_path/dkms.conf
	modlist+=" ${modules[$i]}"
done
echo "rv" >> $src_path/modules-load.conf
echo "/etc/depmod.d/$debname.conf" >> $src_path/$debname.files

# build the tarball
echo "Copy the working files from $srcdir/$kerneldir"
echo "Copy the working files to $tardir"
cp $src_path/dkms.conf $tardir
pushd $srcdir/$kerneldir
for (( i = 0 ; i <= modules_cnt ; i++ ))
do
	cp ${files_to_copy[$i]} $tardir/${modules[$i]}/
done
echo "Copying header files"
for (( i = 0 ; i < include_dirs_cnt ; i++ ))
do
        mkdir -p $tardir/${include_dirs[$i]}
        cp ${include_files_to_copy[$i]} $tardir/${include_dirs[$i]}/
done
echo before popd cp $srcdir/$kerneldir/LICENSE $tardir/.
cp $srcdir/$kerneldir/LICENSE $tardir/.
popd
echo "Building tar file"
echo tardir is $tardir
(cd $tardir; tar cfz - --transform="s,^,${debname}-${debversion}/," *) > \
	debbuild/$debname-$debversion.tgz
cd $workdir

cp -R $filedir/debian $tardir

sed -i "s/@DEBNAME@/$debname/g" $tardir/debian/*
sed -i "s/@DEBRELEASE@/$debrelease/g" $tardir/debian/*
sed -i "s/@DEBVERSION@/$debversion/g" $tardir/debian/*
sed -i "s/@MODLIST@/$modlist/g" $tardir/debian/*

if [[ -n "$MVERSION" ]]; then
	sed -i "s/mversion=@MVERSION@/mversion=${MVERSION}/" $tardir/debian/*
else
	sed -i "/mversion=@MVERSION@/d" $tardir/debian/*
fi

# moment of truth, build package

cd $tardir
dpkg-buildpackage
ret=$?

exit $ret