# AWS teardown, 2026-10-06

The Sendable AWS account `560151615499` (ca-central-1) is empty. The backend no
longer runs on Fargate. `docs/PIPELINE.md` and the `copilot/` manifests describe
infrastructure that does not exist any more.

## What the teardown deleted

The compute was already gone before this teardown. ECS, the public load balancer,
and the RDS instance stopped billing around 2026-09-01, the snapshot date.

This teardown deleted the rest:

- SES receipt rule set `inboxhealth-rules` and the rule `dmarc-to-s3`.
- SES identities `sndbl.com`, `ag.sndbl.com`, `te2017r@gmail.com`.
- Security group `inboxhealth-db-sg`, which blocked the stack delete.
- CloudFormation stack `inboxhealth-prod`.
- The Copilot application `inboxhealth`: StackSet, roles stack, pipeline bucket.
- ECR repositories `inboxhealth-api` and `inboxhealth/api`, 23 images.
- RDS manual snapshot `sndbl-final-20260813`, 20 GB. **The only copy of the
  production database. It is unrecoverable.**
- S3 bucket `inboxhealth-dmarc-reports-prod`, 140 raw DMARC reports.
- SQS queues `inboxhealth-audit`, `inboxhealth-dmarc-ingest`, `inboxhealth-report`.
- 6 SSM secret parameters, 10 Lambda log groups, the `api.sndbl.com` ACM
  certificate, the `rds-monitoring-role` IAM role, and one EventBridge rule.

## What is left

- KMS customer key `6cd056fb-22b9-42d9-b545-e525ff2072c5`. AWS deletes it on
  2026-10-13. KMS enforces a 7-day minimum wait.
- IAM user `inboxhealth-admin` and its access key. The account closure removes it.
- The default VPC and its default security group. These cost nothing.

## The account is closed

George closed the account as root on 2026-10-06. The AWS console shows "The
account is closed". The `inboxhealth-admin` access key now fails with
`InvalidClientTokenId`, which proves the closure took effect.

AWS keeps the account recoverable through AWS Support until **2027-01-04**, 90
days after closure. After that date AWS deletes it permanently. The account email
address cannot start a new AWS account before that date. A final bill for October
usage, about $0.30 plus tax, arrives in early November.

## Done after the teardown

- Porkbun DNS is clean. George deleted the 6 SES DKIM CNAMEs, the ACM validation
  CNAME, the `_amazonses.ag.sndbl.com` verification TXT, the dead `api.sndbl.com`
  record, and the `ag.sndbl.com` MX record. A check of `sndbl.com`,
  `ag.sndbl.com`, and every subdomain finds no AWS reference.
- The OpenAI API key is deleted.
- The local AWS credentials are gone. `~/.aws/credentials` and `~/.aws/config`
  are in the Trash. The 6 AWS lines in `production/backend/.env` are removed:
  `AWS_REGION`, `AWS_SQS_AUDIT_URL`, `AWS_SQS_REPORT_URL`, `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, and their comment.
- A sweep of all 17 enabled regions found no EC2, EBS, EIP, NAT gateway, RDS
  instance, RDS snapshot, load balancer, ECS cluster, Lambda, ECR repository,
  ElastiCache cluster, or CloudFormation stack.
- The account holds no Savings Plan, no Reserved Instance, no Route 53 domain, no
  Marketplace subscription, and no paid Support plan. It belongs to no AWS
  Organization.

## Known dead pointer, not AWS

`_dmarc.sndbl.com` still reads
`v=DMARC1; p=reject; rua=mailto:749f285f2d0aa1f4@ag.sndbl.com; ...`. The `rua=`
mailbox was the SES ingestion address and no longer exists. The `p=reject`
policy still works. Only the report delivery fails. Remove the `rua=` part to
stop the failed deliveries.
