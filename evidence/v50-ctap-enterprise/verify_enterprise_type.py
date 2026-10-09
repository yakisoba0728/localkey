#!/usr/bin/env python3
"""Independent python-fido2 CTAPHID test of CTAP2.1 enterpriseAttestation CBOR type."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from fido2.ctap import CtapError


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',required=True,type=Path)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--expect',required=True,choices=('baseline','fixed'))
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    root=args.root.resolve()
    sys.path.insert(0,str(root/'tools'))
    from verify_ctap import Fixture
    observations=[]
    with tempfile.TemporaryDirectory(prefix='ske-ep-type-',dir='/tmp') as directory:
        fixture=Fixture(args.binary.resolve(),Path(directory))
        try:
            ctap=fixture.start()
            before=ctap.get_info().remaining_disc_creds
            for label,value in [('uint1',1),('uint2',2),('uint0',0),('uint3',3),('bool_true',True)]:
                try:
                    ctap.make_credential(
                        hashlib.sha256(b'ep-type '+label.encode()).digest(),
                        {'id':'localhost','name':'Local fixture'},
                        {'id':label.encode()},
                        [{'type':'public-key','alg':-7}],
                        options={'rk':False},
                        enterprise_attestation=value,
                    )
                except CtapError as error:
                    status=int(error.code)
                else:
                    status=0
                after=ctap.get_info().remaining_disc_creds
                observations.append({'request':label,'status':status,'remaining_before':before,'remaining_after':after})
        finally:
            fixture.stop()
    expected_int=0x11 if args.expect=='baseline' else 0x02
    expected_bool=0x02 if args.expect=='baseline' else 0x11
    passed=all(row['status']==(expected_bool if row['request']=='bool_true' else expected_int) and row['remaining_before']==row['remaining_after'] for row in observations)
    report={'passed':passed,'expect':args.expect,'observations':observations,
            'official_spec':'https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#makecred-enterpriseattestation',
            'transport':'unmodified python-fido2 over private Unix CTAPHID','physical_device_access':False}
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':passed,'statuses':{row['request']:row['status'] for row in observations}}))
    if not passed:raise SystemExit(1)

if __name__=='__main__':main()
