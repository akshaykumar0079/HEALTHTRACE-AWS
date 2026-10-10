# Adding AWS later (optional, off by default)

AWS is **off** (`AWS_MODE=off`) in hosted config and **mock** locally. In mock
mode alerts are written to `data/aws_mock.log`; nothing contacts AWS.
Integration labels in the UI: MOCK, NOT CONFIGURED, CONFIGURED, ERROR.
"Configured" means settings are present; a status only becomes *verified*
after a real successful call. Brevo email does **not** satisfy the Acentra
CloudWatch/SNS requirement.

To enable it yourself:

1. Deploy `deploy/aws/*.yaml` (creates the log group, SNS topic and a
   least-privilege role: `logs:CreateLogStream`, `logs:PutLogEvents`,
   `sns:Publish` on those resources only; never AdministratorAccess).
2. Authenticate with your own profile/SSO/task role (never paste keys into the
   app or chat).
3. Set `AWS_MODE=live`, `AWS_REGION`, `CLOUDWATCH_LOG_GROUP`, `SNS_TOPIC_ARN`.
4. Use *AWS integration > Test* and confirm in the CloudWatch console / SNS
   subscriber. See `docs/aws-iam.md` and `docs/aws-deployment.md`.
