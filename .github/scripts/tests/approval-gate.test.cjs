"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {verifyProtection, verifyApproval} = require("../approval-gate.cjs");

function fixture() {
  const environment = {
    protection_rules: [{
      type: "required_reviewers", prevent_self_review: true,
      reviewers: [{type: "User", reviewer: {login: "hvaandres"}}],
    }],
    deployment_branch_policy: {custom_branch_policies: true},
  };
  const policies = [{name: "main", type: "branch"}];
  const reviews = [{
    state: "approved", user: {login: "hvaandres"},
    environments: [{name: "keyvault-apply"}],
  }];
  const context = {
    ref: "refs/heads/main", actor: "requester", runId: 123, runAttempt: 1,
    repo: {owner: "test-owner", repo: "test-repo"},
  };
  const github = {
    rest: {repos: {
      getEnvironment: async () => ({data: environment}),
      listDeploymentBranchPolicies: () => {},
    }},
    paginate: async () => policies,
    request: async (route, args) => {
      assert.equal(route, "GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals");
      assert.equal(args.run_id, 123);
      return {data: reviews};
    },
  };
  return {github, context, environment, policies, reviews};
}

test("only hvaandres can approve a protected deployment", async () => {
  const state = fixture();
  await verifyProtection(state, "keyvault-apply");
  await verifyApproval(state, "keyvault-apply");
});

for (const name of [
  "privatelink-apply", "resource-request-approval",
  "keyvault-cyber-dev-apply", "keyvault-cyber-tst-apply", "keyvault-cyber-prd-apply",
]) {
  test(`${name} uses the same named approval policy`, async () => {
    const state = fixture();
    state.reviews[0].environments[0].name = name;
    await verifyApproval(state, name);
  });
}

for (const [name, mutate] of [
  ["different reviewer", s => { s.environment.protection_rules[0].reviewers[0].reviewer.login = "someone-else"; }],
  ["team reviewer", s => { s.environment.protection_rules[0].reviewers[0].type = "Team"; }],
  ["additional reviewer", s => { s.environment.protection_rules[0].reviewers.push({type: "User", reviewer: {login: "alternate"}}); }],
  ["missing reviewer rule", s => { s.environment.protection_rules = []; }],
  ["self-review permitted", s => { s.environment.protection_rules[0].prevent_self_review = false; }],
  ["unrestricted deployment branches", s => { s.environment.deployment_branch_policy.custom_branch_policies = false; }],
  ["extra deployment branch", s => { s.policies.push({name: "feature", type: "branch"}); }],
  ["main tag instead of branch", s => { s.policies[0].type = "tag"; }],
  ["non-main request", s => { s.context.ref = "refs/heads/feature"; }],
]) {
  test(`rejects ${name}`, async () => {
    const state = fixture();
    mutate(state);
    await assert.rejects(verifyProtection(state, "keyvault-apply"));
  });
}

for (const [name, mutate] of [
  ["no actual approval", s => { s.reviews.length = 0; }],
  ["approval by someone else", s => { s.reviews[0].user.login = "someone-else"; }],
  ["rejected request", s => { s.reviews[0].state = "rejected"; }],
  ["approval for another environment", s => { s.reviews[0].environments[0].name = "privatelink-apply"; }],
  ["self-approved request", s => { s.context.actor = "hvaandres"; }],
  ["previous-attempt approval", s => { s.context.runAttempt = 2; }],
]) {
  test(`rejects ${name}`, async () => {
    const state = fixture();
    mutate(state);
    await assert.rejects(verifyApproval(state, "keyvault-apply"));
  });
}

test("checks the latest review for the specific environment", async () => {
  const state = fixture();
  state.reviews.unshift({
    state: "rejected", user: {login: "hvaandres"},
    environments: [{name: "privatelink-apply"}],
  });
  await verifyApproval(state, "keyvault-apply");
  state.reviews.unshift({
    state: "rejected", user: {login: "hvaandres"},
    environments: [{name: "keyvault-apply"}],
  });
  await assert.rejects(verifyApproval(state, "keyvault-apply"));
});

test("unknown environments and inaccessible settings fail closed", async () => {
  const state = fixture();
  await assert.rejects(verifyProtection(state, "unprotected-environment"));
  state.github.rest.repos.getEnvironment = async () => { throw new Error("Not found"); };
  await assert.rejects(verifyProtection(state, "keyvault-apply"));
});

test("missing environment returns setup instructions", async () => {
  const state = fixture();
  const error = Object.assign(new Error("Not Found"), {status: 404});
  state.github.rest.repos.getEnvironment = async () => { throw error; };
  await assert.rejects(
    verifyProtection(state, "keyvault-cyber-prd-apply"),
    /Environment 'keyvault-cyber-prd-apply' does not exist/,
  );
});
