#!/bin/bash

DEFAULT_KERNEL_VERSION=$(uname -r)
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
rpmname="iefs-kernel-updates"

set -e

if [[ -e /etc/os-release ]]; then
	. /etc/os-release
	if [[ "$ID" == "sle_hpc" ]]; then
		ID="sles"
	fi
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

is_up_kernel="No"
# $1 - Current running kernel (eg "4.18.0-305.el8.x86_64")
# $2 - Minimum upstream kernel version (eg "5.17.0")
# Return
#      Set is_up_kernel to "Yes" if so.
function check_upstream_kernel() {
	cur=$1;
	up=$2;

	# Remove any trailing version info
	cur=${cur%%-*}
	up=${up%%-*}

	# Get major version number and remove it from the version string
	cur_mj=${cur%%.*}
	up_mj=${up%%.*}
	cur=${cur#*.}
	up=${up#*.}

	# Get patch level and sublevel version info
	cur_pl=${cur%%.*}
	cur_sl=${cur#*.}
	up_pl=${up%%.*}
	up_sl=${up#*.}

	# Build the complete versions into numbers and compare
	#echo " cur: mj = $cur_mj, pl = $cur_pl, sl = $cur_sl"
	#echo " up: mj = $up_mj, pl = $up_pl, sl = $up_sl"
	#cur_num=$(( $cur_mj << 16 + $cur_pl << 8 + $cur_sl ))
	cur_num=0
	(( cur_num += (cur_mj << 16) ))
	(( cur_num += (cur_pl << 8) ))
	(( cur_num += cur_sl ))
	#up_num=$(( $up_mj << 16 + $up_pl << 8 + $up_sl ))
	up_num=0
	(( up_num += (up_mj << 16) ))
	(( up_num += (up_pl << 8) ))
	(( up_num += up_sl ))
	#echo "cur_num = $cur_num, up_num = $up_num"
	# For some reason, "return X" exits the entire script, not just
	# this function.
	if [[ $cur_num -ge $up_num ]]; then
		is_up_kernel="Yes";
	fi
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
upstream_kernel="5.17.0"
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

# Check if the running kernel is a upstream kernel.
# Be sure to update upstream_kernel variable when a new
# distro with a newer kernel is introduced.

echo "kernel_version = $DEFAULT_KERNEL_VERSION"
echo "upstream_kernel = $upstream_kernel"
check_upstream_kernel ${DEFAULT_KERNEL_VERSION} ${upstream_kernel}
if [[ $is_up_kernel == "Yes" ]]; then
	compat_dir=UPSTRM;
elif [[ $ID == "rhel" ]]; then
	compat_dir=RH$VERSION_ID_MAJOR$VERSION_ID_MINOR
elif [[ $ID == "sles" ]]; then
	if [[ -z $VERSION_ID_MINOR ]]; then
		compat_dir=SLES$VERSION_ID_MAJOR
	else
		compat_dir=SLES${VERSION_ID_MAJOR}SP${VERSION_ID_MINOR}
	fi
fi
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
echo "INTEL GPU env var: $INTEL_GPU_DIRECT"

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
	rpmrelease=$(git rev-list WFR_driver_first..HEAD -- $srcdir | wc -l)
	echo "ifs-all build"
else
	rpmrelease=$(cd "$srcdir"; git rev-list "WFR_driver_first..HEAD" | wc -l)
	echo "wfr-linux-devel build"
fi
rpmrelease=$((rpmrelease + 5000))
if [ $gpubuild = 'true' ]; then
	if [ "$INTEL_GPU_DIRECT" != "" ]; then
		rpmrelease+="oneapize"
	else
		rpmrelease+="cuda"
	fi
fi
echo "rpmrelease = $rpmrelease"

echo "Setting up RPM build area"
mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# make sure rpm component strings are clean, should be no-ops
rpmname=$(echo "$rpmname" | sed -e 's/[.]/_/g')
rpmversion=$(echo "$DEFAULT_KERNEL_VERSION" | sed -e 's/-/_/g')
rpmrequires=$(echo "$DEFAULT_KERNEL_VERSION" | sed -e 's/.[^.]*$//')

# get kernel(-devel) rpm version and release values
if [ $distro = 'rhel' ]
then
	if [ $is_up_kernel = "Yes" ]; then
		 kernel_rpmver=${DEFAULT_KERNEL_VERSION%%-*}
	else
		kernel_rpmver=$(rpm -q --qf %{VERSION} kernel-$(uname -r))
	fi
	kmod_subdir=extra
else
	if [ $is_up_kernel = "Yes" ]; then
		kernel_rpmver=${DEFAULT_KERNEL_VERSION%%-*}
	else
		kernel_rpmver=$(rpm -q --qf %{VERSION} kernel-default)
	fi
	kmod_subdir=updates
fi
# create a new $rpmname.conf and $rpmname.files
src_path=$workdir/rpmbuild/SOURCES/

# prepare files list and depmod config for every module built
echo "%defattr(644,root,root,755)" > $src_path/$rpmname.files
cat > $src_path/dkms.conf << EOF
MAKE="make -C \${kernel_source_dir} MVERSION=${MVERSION} CONFIG_INFINIBAND_RV=m M=\${dkms_tree}/${rpmname}/${rpmrelease}/build"
CLEAN="make clean"
PACKAGE_NAME="${rpmname}"
PACKAGE_VERSION="${rpmrelease}"
AUTOINSTALL="yes"
EOF

modlist=""
for (( i = 0 ; i <= modules_cnt ; i++ ))
do
        echo "override ${modules[$i]} $kernel_rpmver-* weak-updates/${modules[$i]}" >> $src_path/$rpmname.conf
        echo "/lib/modules/%2-%1/$kmod_subdir/$rpmname/${modules[$i]}.ko" >> $src_path/$rpmname.files
        echo "BUILT_MODULE_NAME[$i]='${modules[$i]}'" >> $src_path/dkms.conf
        echo "BUILT_MODULE_LOCATION[$i]='${modules[$i]}/'" >> $src_path/dkms.conf
        echo "DEST_MODULE_LOCATION[$i]='/$kmod_subdir/$rpmname'" >> $src_path/dkms.conf
	modlist+=" ${modules[$i]}"
done
echo "rv" >> $src_path/modules-load.conf
echo "/etc/depmod.d/$rpmname.conf" >> $src_path/$rpmname.files

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
cp $srcdir/$kerneldir/LICENSE $tardir/.
popd
echo "Building tar file"
(cd $tardir; tar cfz - --transform="s,^,${rpmname}-${rpmversion}/," *) > \
	rpmbuild/SOURCES/$rpmname-$rpmversion.tgz
cd $workdir

# create the spec file
echo "Creating spec file"

if [ $distro = 'rhel' ]
then
	cp $filedir/$rpmname.spec.rhel $workdir/rpmbuild/SPECS/$rpmname.spec
else
	cp $filedir/$rpmname.spec.sles $workdir/rpmbuild/SPECS/$rpmname.spec
fi

sed -i "s/RPMNAME/$rpmname/g" $workdir/rpmbuild/SPECS/$rpmname.spec
sed -i "s/RPMRELEASE/$rpmrelease/g" $workdir/rpmbuild/SPECS/$rpmname.spec
sed -i "s/RPMVERSION/$rpmversion/g" $workdir/rpmbuild/SPECS/$rpmname.spec
sed -i "s/MODLIST/$modlist/g" $workdir/rpmbuild/SPECS/$rpmname.spec

if [ $VERSION_ID = '8.0' -o $is_up_kernel = 'Yes' ]; then
	sed -i "s/kernel_source/kbuild/g" $workdir/rpmbuild/SPECS/$rpmname.spec
fi
if [[ -n "$MVERSION" ]]; then
	sed -i "s/mversion MVERSION/mversion \"${MVERSION}\"/" $workdir/rpmbuild/SPECS/$rpmname.spec
else
	sed -i "/mversion MVERSION/d" $workdir/rpmbuild/SPECS/$rpmname.spec
fi

# moment of truth, run rpmbuild
rm -rf ksrc
echo "Building SRPM"
cd rpmbuild
rpmbuild -bs --define "_topdir $(pwd)" SPECS/${rpmname}.spec
ret=$?

exit $ret
