#!/bin/bash
ROOTDIR=/nvme/tmp
DATADIR=$ROOTDIR/capella
GETH=./build/bin/geth

rm -rf $DATADIR/geth
$GETH --datadir $DATADIR init $DATADIR/genesis.json
$GETH --http \
        --datadir=$DATADIR \
        --nodiscover \
        --syncmode=full \
        --allow-insecure-unlock \
		--unlock=0x123463a4b065722e99115d6c222f267d9cabb524 \
        --password=$DATADIR/geth_password.txt \
        --mine \
        --authrpc.jwtsecret=/nvme/tmp/capella/jwtsecret.txt console
