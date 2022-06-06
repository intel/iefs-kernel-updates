#!/bin/bash
# $1 = directory with clone of wfr-linux-devel and checkout of hpc-eth-for-next
usage()
{
	echo "Usage: ./diff_upstream.sh wfr-linux-devel" >&2
	exit 2
}

wfrsrc=$1
if [ -z "$wfrsrc" ]
then
	usage
fi

if [ ! -d $wfrsrc/drivers/infiniband/ulp/rv -o ! -f $wfrsrc/include/uapi/rdma/rv_user_ioctls.h ]
then
	echo "$wfrsrc: does not contain rv driver" >&2
	usage
fi

tmpdir=tmp-unifdef
rm -rf $tmpdir
mkdir $tmpdir
cp -r  drivers/infiniband/ulp/rv $tmpdir/rv/
cp -r include/uapi/rdma $tmpdir/inc/

find $tmpdir -type f -regex ".*\.[ch]$" -exec unifdef -k -m -DRV_ENABLE_DRAIN_TIMEOUT -URV_ENABLE_DUP_SQ_CQE_CHECK -DDRAIN_WQ -UNVIDIA_GPU_DIRECT -URV_REG_MR_DISCRETE -DRV_REG_MR_PD_UOBJECT -UNO_ERR_TO_ERR -DUSE_IB_DRAIN -URNDV_LOCAL_ERR_TEST -DHAS_DEV_RENAME -DMMU_NOTIFIER_RANGE_START_USES_MMU_NOTIFIER_RANGE -UNO_RB_ROOT_CACHE {} \;

{
diff -B -b -r $wfrsrc/drivers/infiniband/ulp/rv $tmpdir/rv
diff -B -b $wfrsrc/include/uapi/rdma/rv_user_ioctls.h $tmpdir/inc/rv_user_ioctls.h
} 2>&1|tee diff.res

