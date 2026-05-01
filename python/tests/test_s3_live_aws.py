"""Live S3 round-trip against real AWS.

Uses whatever boto3 finds in the default chain (~/.aws/credentials, env
vars, IMDS, etc). Creates a one-shot test bucket, writes tn.log entries
through the S3Handler, lists + reads the object back, verifies each
envelope's signature, empties + deletes the bucket.

Skips cleanly if credentials or boto3 are missing.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


def main() -> int:
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        print("SKIP: boto3 not installed (pip install 'tn-protocol[s3]')")
        return 0

    try:
        sts = boto3.client("sts")
        ident = sts.get_caller_identity()
        account = ident["Account"]
        print(f"aws account: {account}  arn: {ident['Arn']}")
    except (NoCredentialsError, ClientError) as e:
        print(f"SKIP: no AWS credentials ({e})")
        return 0

    import tn

    run_id = uuid.uuid4().hex[:10]
    # S3 bucket names: DNS-safe lowercase, 3-63 chars, globally unique.
    bucket = f"tn-test-{account[-6:]}-{run_id}"[:60]
    region = os.environ.get("AWS_REGION") or "us-east-1"

    s3 = boto3.client("s3", region_name=region)

    print(f"creating bucket: s3://{bucket} (region={region})")
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": region},
        )

    try:
        # ---- write via handler ----------------------------------------
        with tempfile.TemporaryDirectory(prefix="tns3_") as td:
            ws = Path(td)
            yaml_path = ws / "tn.yaml"
            tn.init(yaml_path)
            base = yaml_path.read_text(encoding="utf-8")
            block = f"""
handlers:
  - name: local
    kind: file.rotating
    path: ./.tn/logs/tn.ndjson
    max_bytes: 524288
  - name: s3_bronze
    kind: s3
    bucket: {bucket}
    region: {region}
    prefix: tn/{run_id}
    batch_max_rows: 3               # force flush after 3 events
    batch_window_sec: 2
    filter:
      event_type:
        starts_with: "s3_"
"""
            yaml_path.write_text(base + block, encoding="utf-8")
            tn.flush_and_close()
            tn.init(yaml_path)

            sent_ids: list[str] = []
            for i in range(3):
                env = tn.log("s3_ping", seq=i, run_id=run_id, note="s3 live test")
                sent_ids.append(env["event_id"])
            print(f"produced {len(sent_ids)} events; draining handler outbox")
            tn.flush_and_close(timeout=30.0)

        # ---- list + verify --------------------------------------------
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=f"tn/{run_id}/")
        objects = resp.get("Contents", [])
        print(f"listed {len(objects)} object(s) under s3://{bucket}/tn/{run_id}/")
        assert len(objects) >= 1, "expected at least one object"

        got_envs: list[dict] = []
        for obj in objects:
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            print(f"  {obj['Key']}  {obj['Size']} bytes")
            for line in body.splitlines():
                if line.strip():
                    got_envs.append(json.loads(line))

        got_ids = [e["event_id"] for e in got_envs]
        ok = set(got_ids) == set(sent_ids)
        print(f"retrieved {len(got_envs)} envelopes; ids match: {ok}")

        # signature check on the stored JSON
        from tn.signing import DeviceKey, _signature_from_b64

        sig_ok = sum(
            1
            for env in got_envs
            if DeviceKey.verify(
                env["did"],
                env["row_hash"].encode("ascii"),
                _signature_from_b64(env["signature"]),
            )
        )
        print(f"signatures verify after S3 round-trip: {sig_ok}/{len(got_envs)}")
        if sig_ok != len(got_envs):
            ok = False

        return 0 if ok else 1

    finally:
        # -------- cleanup: empty + delete the bucket -------------------
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            if resp.get("Contents"):
                s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in resp["Contents"]]},
                )
            s3.delete_bucket(Bucket=bucket)
            print(f"cleaned up bucket: {bucket}")
        except Exception as e:
            print(f"WARN: cleanup failed (harmless): {e}")


if __name__ == "__main__":
    sys.exit(main())
