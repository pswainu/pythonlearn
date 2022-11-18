

def create_deny_policy(project_id: str, policy_id: str) -> None:
    from google.cloud import iam_v2
    from google.cloud.iam_v2 import types
    
    policies_client = iam_v2.PoliciesClient()

    attachment_point = f"cloudresourcemanager.googleapis.com%2Fprojects%2F{project_id}"

    deny_rule = types.DenyRule()
    
    deny_rule.denied_principals = ["principalSet://goog/public:all"]
    deny_rule.denied_permissions = [
        "cloudresourcemanager.googleapis.com/projects.delete"
    ]

    
    deny_rule.denial_condition = {
        "expression": "!resource.matchTag('12345678/env', 'test')"
    }

    # Add the deny rule and a description for it.
    policy_rule = types.PolicyRule()
    policy_rule.description = "block all principals from deleting projects, unless the principal is a member of project-admins@example.com and the project being deleted has a tag with the value test"
    policy_rule.deny_rule = deny_rule

    policy = types.Policy()
    policy.display_name = "Restrict project deletion access"
    policy.rules = [policy_rule]

    # Set the policy resource path, policy rules and a unique ID for the policy.
    request = types.CreatePolicyRequest()
    # Construct the full path of the resource's deny policies.
    # Its format is: "policies/{attachmentPoint}/denypolicies"
    request.parent = f"policies/{attachment_point}/denypolicies"
    request.policy = policy
    request.policy_id = policy_id

    # Build the create policy request and wait for the operation to complete.
    result = policies_client.create_policy(request=request).result()
    print(f"Created the deny policy: {result.name.rsplit('/')[-1]}")


if __name__ == "__main__":
    import uuid

    # Your Google Cloud project ID.
    project_id = "your-google-cloud-project-id"
    # Any unique ID (0 to 63 chars) starting with a lowercase letter.
    policy_id = f"deny-{uuid.uuid4()}"

    # Test the policy lifecycle.
    create_deny_policy(project_id, policy_id)