"use strict";

const APPROVER = "hvaandres";
const ENVIRONMENTS = new Set([
  "keyvault-apply", "privatelink-apply", "resource-request-approval",
  "keyvault-cyber-dev-apply", "keyvault-cyber-tst-apply", "keyvault-cyber-prd-apply",
  "keyvault-cyber-dev-plan", "keyvault-cyber-tst-plan", "keyvault-cyber-prd-plan",
]);

async function verifyProtection({github, context}, environmentName) {
  if (process.env.REQUIRE_APPROVAL === "false") {
    return;
  }
  if (!ENVIRONMENTS.has(environmentName) || context.ref !== "refs/heads/main") {
    throw new Error("Unknown approval environment or non-main request.");
  }
  const args = {...context.repo, environment_name: environmentName};
  let environment;
  try {
    ({data: environment} = await github.rest.repos.getEnvironment(args));
  } catch (error) {
    if (error.status === 404 || error.response?.status === 404) {
      throw new Error(
        `GitHub Environment '${environmentName}' does not exist. Create it in Settings > Environments, ` +
        "require only hvaandres with self-review disabled, and allow exactly one main-branch deployment policy.",
      );
    }
    throw error;
  }
  const reviews = environment.protection_rules.filter(rule => rule.type === "required_reviewers");
  const review = reviews[0];
  if (reviews.length !== 1 || !review.prevent_self_review ||
      review.reviewers?.length !== 1 || review.reviewers[0].type !== "User" ||
      review.reviewers[0].reviewer?.login?.toLowerCase() !== APPROVER) {
    throw new Error(`${environmentName} must require only ${APPROVER}, with self-review disabled.`);
  }
  if (!environment.deployment_branch_policy?.custom_branch_policies) {
    throw new Error(`${environmentName} must allow only main.`);
  }
  const policies = await github.paginate(github.rest.repos.listDeploymentBranchPolicies, args);
  if (policies.length !== 1 || policies[0].name !== "main" ||
      (policies[0].type && policies[0].type !== "branch")) {
    throw new Error(`${environmentName} must have exactly one branch policy: main.`);
  }
}

async function verifyApproval({github, context}, environmentName) {
  if (process.env.REQUIRE_APPROVAL === "false") {
    return;
  }
  await verifyProtection({github, context}, environmentName);
  // Review-history entries do not identify run attempts. Never reuse old approvals.
  if (Number(context.runAttempt ?? process.env.GITHUB_RUN_ATTEMPT) !== 1) {
    throw new Error("Start a new workflow run; previous-attempt approvals cannot be reused.");
  }
  const {data: reviews} = await github.request(
    "GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals",
    {...context.repo, run_id: context.runId},
  );
  const latest = reviews.find(review => review.environments.some(env => env.name === environmentName));
  if (latest?.state !== "approved" || latest.user?.login?.toLowerCase() !== APPROVER ||
      context.actor?.toLowerCase() === APPROVER) {
    throw new Error(`This environment requires an explicit, non-self approval by ${APPROVER}.`);
  }
}

module.exports = {verifyProtection, verifyApproval};
