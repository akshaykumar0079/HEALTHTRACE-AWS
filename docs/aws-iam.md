# AWS: IAM permissions, resource setup and live verification

HEALTH TRACE talks to exactly two AWS services, and only in `AWS_MODE=live`:

| Service | When | API calls the app makes |
|---|---|---|
| CloudWatch Logs | every alert | `CreateLogGroup` (optional, see below), `CreateLogStream`, `PutLogEvents` |
| SNS | HIGH/CRITICAL incident opened or escalated | `Publish` |
| both | AWS page, "Test connection" (read-only) | `DescribeLogGroups`, `GetTopicAttributes` |

Credentials are never configured in the app. boto3 resolves them through its
default chain: `AWS_PROFILE` / `aws configure` / `aws sso login` on a laptop,
the task role on ECS. Never put access keys in `.env` (it is git-ignored, and
so are `.env.*`, `*.pem` and `*_accessKeys.csv`, but keys still don't belong there).

## Minimum policy

Replace `<region>`, `<account>`, the log group and the topic name.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WriteAlertLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": [
        "arn:aws:logs:<region>:<account>:log-group:/healthtrace/local/alerts",
        "arn:aws:logs:<region>:<account>:log-group:/healthtrace/local/alerts:*"
      ]
    },
    {
      "Sid": "TestConnectionCheck",
      "Effect": "Allow",
      "Action": "logs:DescribeLogGroups",
      "Resource": "*"
    },
    {
      "Sid": "PublishAlerts",
      "Effect": "Allow",
      "Action": ["sns:Publish", "sns:GetTopicAttributes"],
      "Resource": "arn:aws:sns:<region>:<account>:healthtrace-alerts-local"
    }
  ]
}
```

- **`logs:CreateLogGroup` is not needed** when the group already exists
  (both CloudFormation templates create it). The app tries to create the
  group once per stream and treats `AccessDenied` as "pre-created". Add
  `logs:CreateLogGroup` on the same group ARN only if you want the app to
  create the group itself.
- **`logs:DescribeLogGroups` and `sns:GetTopicAttributes`** are used only by the
  read-only "Test connection" button. Alerting works without them.
  `DescribeLogGroups` cannot be scoped to one group, so it needs `"*"`.
- **`logs:FilterLogEvents`** is *not* used by the app. Only
  `scripts/aws_live_check.py` needs it, to read alerts back (the
  `VerifierPolicy` below).
- No `AdministratorAccess`, no `iam:*`, no wildcards on write actions.

## What goes to AWS (PHI review)

- **CloudWatch:** the alert JSON: kind, service or synthetic user ID (e.g.
  `U-117`), severity, score, metrics (counts, rates, z-scores) and an
  explanation such as *"prior_auth error rate 22% vs baseline 2% (z=20.2);
  79 urgent patients affected"*. No patient IDs, names or record contents.
- **SNS:** subject `[MedGuard SEVERITY] <service or user>: <kind>` and the same
  explanation plus the incident ID. Email subscribers receive this text.
- All data in this project is synthetic (`P-000123`-style patient IDs that are
  never sent to AWS).

## Region

The app defaults to `us-east-1` and nothing in the repo pins a region (the
ECS template uses the region you deploy it to). For a team in India,
**`ap-south-1` (Mumbai)** gives the lowest latency. Use one region for
everything: the SNS topic ARN must be in `AWS_REGION`, or publishes fail (the
app warns about this at startup).

## Setup for a laptop demo (alerts-only stack)

`deploy/aws/alerts-only.yaml` creates only the alert log group, the SNS
topic, an optional email subscription, and two managed policies scoped to
those two resources. No VPC, ECS or load balancer. Deleting the stack removes
exactly these resources.

The identity that *creates* the stack needs CloudFormation, SNS, CloudWatch
Logs and `iam:CreatePolicy` permissions. Your normal admin/power-user profile
is fine for this one-off step. The *app* then runs with the minimum policy.

Bash or PowerShell (single-line commands):

```bash
# 0. who am I, and is the CLI pointed at the right account? (shows account + ARN, never keys)
aws sts get-caller-identity --profile <your-profile>

# 1. create the resources (email is optional; confirm the email AWS sends you)
aws cloudformation deploy --profile <your-profile> --region ap-south-1 --stack-name healthtrace-alerts-local --template-file deploy/aws/alerts-only.yaml --capabilities CAPABILITY_IAM --parameter-overrides EnvironmentName=local AlertEmail=you@example.com

# 2. read the outputs: LogGroupName, SnsTopicArn, AppPolicyArn, VerifierPolicyArn
aws cloudformation describe-stacks --profile <your-profile> --region ap-south-1 --stack-name healthtrace-alerts-local --query "Stacks[0].Outputs" --output table
```

### Optional: a least-privilege identity for the app

If you would rather not run the app with your admin profile:

```bash
aws iam create-user --profile <your-profile> --user-name healthtrace-local
aws iam attach-user-policy --profile <your-profile> --user-name healthtrace-local --policy-arn <AppPolicyArn>
aws iam attach-user-policy --profile <your-profile> --user-name healthtrace-local --policy-arn <VerifierPolicyArn>
aws iam create-access-key --profile <your-profile> --user-name healthtrace-local
aws configure --profile healthtrace        # paste the key pair here, on your machine only
```

Then use `--profile healthtrace` below. Delete the key when the hackathon
is over (`aws iam delete-access-key`).

## Live verification (one command)

From the repo root, with the backend installed (`pip install -e "backend[dev]"`):

```bash
python scripts/aws_live_check.py --profile <profile> --region ap-south-1 --stack healthtrace-alerts-local
```

It prints the AWS identity (account and ARN only), then checks, using the
app's own `AwsNotifier` in live mode:

1. configuration (topic ARN format and region match),
2. a synthetic HIGH alert reaches CloudWatch `PutLogEvents`,
3. a synthetic CRITICAL incident is accepted by SNS `Publish`,
4. the alert can be read back from the log group,
5. publishing to a non-existent topic is retried, recorded as failed, and
   does not crash the notifier.

Exit code 0 means every check passed. Test messages are labelled
"HEALTHTRACE live check … synthetic".

## Full app in live mode

Put these in `.env` (no keys):

```
AWS_MODE=live
AWS_REGION=ap-south-1
CLOUDWATCH_LOG_GROUP=/healthtrace/local/alerts
SNS_TOPIC_ARN=<SnsTopicArn>
```

Set the profile in the shell that starts the backend
(bash: `export AWS_PROFILE=<profile>`; PowerShell: `$env:AWS_PROFILE="<profile>"`),
start the generator and backend as in the README, inject *Urgent prior-auth
failure* and *Bulk PHI access* from the dashboard (`Ctrl K`), then:

```bash
python scripts/aws_live_check.py --profile <profile> --region ap-south-1 --stack healthtrace-alerts-local --readback-minutes 15
```

That lists every alert the running app wrote to CloudWatch in the last 15
minutes, grouped by severity. The AWS page in the dashboard shows the
sent/failed/retry counters for both channels.

## Clean-up

```bash
aws cloudformation delete-stack --profile <your-profile> --region ap-south-1 --stack-name healthtrace-alerts-local
```

Detach the policies from `healthtrace-local` first if you created that user
(managed policies can't be deleted while attached), then delete the user.
