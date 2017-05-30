coreo_aws_rule "ec2-vpc-flow-logs" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_ec2-vpc-flow-logs.html"
  display_name "Ensure VPC flow logging is enabled in all VPCs (Scored)"
  suggested_action "VPC Flow Logs be enabled for packet 'Rejects' for VPCs."
  description "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs."
  level "Low"
  meta_cis_id "4.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "iam-unusediamgroup" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
  display_name "Unused or empty IAM group"
  description "There is an IAM group defined without any users in it and therefore unused."
  category "Access"
  suggested_action "Ensure that groups defined within IAM have active users in them. If the groups don't have active users or are not being used, delete the unused IAM group."
  level "Low"
  objectives ["groups", "group"]
  call_modifiers [{}, {:group_name => "groups.group_name"}]
  formulas ["", "count"]
  audit_objects ["", "users"]
  operators ["", "=="]
  raise_when ["", 0]
  id_map "object.group.group_name"
end
coreo_aws_rule "manual-ensure-security-questions" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-ensure-security-questions.html"
  display_name "Ensure Account Security Questions"
  description "Security Questions improve account security"
  category "Security"
  suggested_action "Ensure that the AWS account has security questions registered"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.15"
  meta_cis_scored "false"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end
coreo_aws_rule "manual-detailed-billing" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-detailed-billing.html"
  display_name "Enable Detailed Billing"
  description "Detailed billing can help to bring attention to anomalous use of AWS resources"
  category "Security"
  suggested_action "Ensure that Detailed Billing has been enabled"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.17"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "manual-strategic-iam-roles" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-strategic-iam-roles.html"
  display_name "Ensure Strategic IAM Roles"
  description "Use IAM Master and Manager Roles to optimise security"
  category "Security"
  suggested_action "Implement IAM roles as set out in the CIS document"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.18"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "manual-contact-details" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-contact-details.html"
  display_name "Maintain Contact Details"
  description "Contact details associated with the AWS account may be used by AWS staff to contact the account owner"
  category "Security"
  suggested_action "Ensure that contact details associated with AWS account are current"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.19"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end
coreo_aws_rule "manual-security-contact" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-security-contact.html"
  display_name "Security Contact Details"
  description "Contact details may be provided to the AWS account for your security team, allowing AWS staff to contact them when required"
  category "Security"
  suggested_action "Ensure that security contact information is provided in your AWS account"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.20"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end
coreo_aws_rule "manual-resource-instance-access" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-resource-instance-access.html"
  display_name "IAM Instance Roles"
  description "Proper usage of IAM roles reduces the risk of active, unrotated keys"
  category "Security"
  suggested_action "Ensure IAM instance roles are used for AWS resource access from instances"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.21"
  meta_cis_scored "false"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end
coreo_aws_rule "manual-appropriate-sns-subscribers" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-appropriate-sns-subscribers.html"
  display_name "SNS Appropriate Subscribers"
  description "Unintended SNS subscribers may pose a security risk"
  category "Security"
  suggested_action "Regularly ensure that only appropriate subscribers exist in SNS"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "3.15"
  meta_cis_scored "false"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end
coreo_aws_rule "manual-least-access-routing-tables" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-least-access-routing-tables.html"
  display_name "Least Access Routing Tables"
  description "Being highly selective in peering routing tables minimizes impact of potential breach"
  category "Security"
  suggested_action "Review and minimize routing table access regularly"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "4.5"
  meta_cis_scored "false"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-console-login-without-mfa" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-console-login-without-mfa.html"
  display_name "Ensure console login without MFA has monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Console logins without MFA are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-root-account-usage" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-root-account-usage.html"
  display_name "Ensure root account login has monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Root account logins are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-iam-policy-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-iam-policy-changes.html"
  display_name "Ensure IAM policy changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "IAM policy changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.4"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-cloudtrail-config-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-cloudtrail-config-changes.html"
  display_name "Ensure CloudTrail configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "CloudTrail configuration changes are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-console-auth-failures" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-console-auth-failures.html"
  display_name "Ensure console authentication failures have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Console authentication failures are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.6"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-cmk-change-delete" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-cmk-change-delete.html"
  display_name "Ensure disabled or scheduled deletion of Customer Master Keys (CMKs) have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Disabled and/or scheduled deletion of CMKs are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.7"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-s3-bucket-policy-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-s3-bucket-policy-changes.html"
  display_name "Ensure S3 bucket policy changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "S3 bucket policy changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.8"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-cloudwatch-config-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-cloudwatch-config-changes.html"
  display_name "Ensure CloudWatch configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "CloudWatch configuration changes are not properly monitored and alerted"
  level "Low"
  meta_cis_id "3.9"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-security-group-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-security-group-changes.html"
  display_name "Ensure Security Groups configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Security Groups configuration changes are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.10"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-nacl-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-nacl-changes.html"
  display_name "Ensure Network Access Control Lists (NACL) configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Network Access Control Lists (NACL) configuration changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.11"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-network-gateway-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-network-gateway-changes.html"
  display_name "Ensure Network Gateway configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Network Gateway configuration changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.12"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-route-table-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-route-table-changes.html"
  display_name "Ensure Route Table configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Route Table configuration changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.13"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
coreo_aws_rule "monitor-vpc-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-vpc-changes.html"
  display_name "Ensure VPC configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "VPC configuration changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.14"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end
