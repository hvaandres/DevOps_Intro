"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {verifyProtection, verifyApproval, verifyTeardownProtection, verifyTeardownApproval} = require("../approval-gate.cjs");

function fixture() {
  const environment = {
    protection_rules: [{
      type: "required_reviewers", prevent_self_review: false,
      reviewers: [{type: "User", reviewer: {login: "hvaandres"}}],
    }],
    deployment_branch_policy: {custom_branch_policies: true},
  };
  const policies = [{name: "main", type: "branch"}];
  const reviews = [{
    state: "approved", user: {login: "hvaandres"},
    environments: [{name: "azure-apply"}],
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
  await verifyProtection(state, "azure-apply");
  await verifyApproval(state, "azure-apply");
});

test("old service-specific environment approvals do not authorize renamed jobs", async () => {
  for (const name of ["keyvault-apply", "privatelink-apply", "keyvault-cybersecurity-prd-plan", "terraform-cybersecurity-prd-teardown"]) {
    await assert.rejects(verifyProtection(fixture(), name), /Unknown approval environment/);
  }
});

for (const subscription of ["stg", "tst", "prd"]) {
  test(`teardown ${subscription} requires its own explicit approval`, async () => {
    const state = fixture();
    const name = `azure-cybersecurity-${subscription}-teardown`;
    process.env.REQUIRE_APPROVAL = "true";
    try {
      await verifyTeardownProtection(state, name);
      await assert.rejects(verifyTeardownApproval(state, name), /explicit approval/);
      state.reviews[0].environments[0].name = name;
      await verifyTeardownApproval(state, name);
      state.context.runAttempt = 2;
      await assert.rejects(verifyTeardownApproval(state, name), /new workflow run/);
    } finally {
      delete process.env.REQUIRE_APPROVAL;
    }
  });
}

test("teardown has no approval bypass, even when legacy checks are disabled", async () => {
  for (const value of ["false", "", undefined]) {
    const state = fixture();
    if (value === undefined) delete process.env.REQUIRE_APPROVAL;
    else process.env.REQUIRE_APPROVAL = value;
    try {
      await assert.rejects(verifyTeardownProtection(state, "azure-cybersecurity-stg-teardown"), /cannot be bypassed/);
      await assert.rejects(verifyTeardownApproval(state, "azure-cybersecurity-stg-teardown"), /cannot be bypassed/);
    } finally {
      delete process.env.REQUIRE_APPROVAL;
    }
  }
});

test("teardown cannot reuse the planning or ordinary deployment environment", async () => {
  process.env.REQUIRE_APPROVAL = "true";
  try {
    for (const name of ["azure-cybersecurity-stg-teardown-plan", "azure-apply", "azure-cybersecurity-stg-plan"]) {
      await assert.rejects(verifyTeardownApproval(fixture(), name), /another environment/);
    }
  } finally {
    delete process.env.REQUIRE_APPROVAL;
  }
});

test("hvaandres can explicitly approve their own request", async () => {
  const state = fixture();
  state.context.actor = "hvaandres";
  await verifyProtection(state, "azure-apply");
  await verifyApproval(state, "azure-apply");
});

test("solo requests still require an actual hvaandres approval", async () => {
  const state = fixture();
  state.context.actor = "hvaandres";
  state.reviews.length = 0;
  await assert.rejects(verifyApproval(state, "azure-apply"), /explicit approval/);
});

test("solo requests cannot use another person's approval", async () => {
  const state = fixture();
  state.context.actor = "hvaandres";
  state.reviews[0].user.login = "someone-else";
  await assert.rejects(verifyApproval(state, "azure-apply"), /explicit approval/);
});

test("independent review also works if an environment still prevents self-review", async () => {
  const state = fixture();
  state.environment.protection_rules[0].prevent_self_review = true;
  await verifyApproval(state, "azure-apply");
});

for (const name of [
  "azure-apply", "resource-request-approval",
  "azure-cybersecurity-stg-plan", "azure-cybersecurity-tst-plan", "azure-cybersecurity-prd-plan",
]) {
  test(`${name} uses the same named approval policy`, async () => {
    const state = fixture();
    state.context.actor = "hvaandres";
    state.reviews[0].environments[0].name = name;
    await verifyApproval(state, name);
  });
}

for (const [name, mutate] of [
  ["different reviewer", s => { s.environment.protection_rules[0].reviewers[0].reviewer.login = "someone-else"; }],
  ["team reviewer", s => { s.environment.protection_rules[0].reviewers[0].type = "Team"; }],
  ["additional reviewer", s => { s.environment.protection_rules[0].reviewers.push({type: "User", reviewer: {login: "alternate"}}); }],
  ["missing reviewer rule", s => { s.environment.protection_rules = []; }],
  ["unrestricted deployment branches", s => { s.environment.deployment_branch_policy.custom_branch_policies = false; }],
  ["extra deployment branch", s => { s.policies.push({name: "feature", type: "branch"}); }],
  ["main tag instead of branch", s => { s.policies[0].type = "tag"; }],
  ["non-main request", s => { s.context.ref = "refs/heads/feature"; }],
]) {
  test(`rejects ${name}`, async () => {
    const state = fixture();
    mutate(state);
    await assert.rejects(verifyProtection(state, "azure-apply"));
  });
}

for (const [name, mutate] of [
  ["no actual approval", s => { s.reviews.length = 0; }],
  ["approval by someone else", s => { s.reviews[0].user.login = "someone-else"; }],
  ["rejected request", s => { s.reviews[0].state = "rejected"; }],
  ["approval for another environment", s => { s.reviews[0].environments[0].name = "azure-cybersecurity-tst-plan"; }],
  ["previous-attempt approval", s => { s.context.runAttempt = 2; }],
]) {
  test(`rejects ${name}`, async () => {
    const state = fixture();
    mutate(state);
    await assert.rejects(verifyApproval(state, "azure-apply"));
  });
}

test("checks the latest review for the specific environment", async () => {
  const state = fixture();
  state.reviews.unshift({
    state: "rejected", user: {login: "hvaandres"},
    environments: [{name: "azure-cybersecurity-tst-plan"}],
  });
  await verifyApproval(state, "azure-apply");
  state.reviews.unshift({
    state: "rejected", user: {login: "hvaandres"},
    environments: [{name: "azure-apply"}],
  });
  await assert.rejects(verifyApproval(state, "azure-apply"));
});

test("unknown environments and inaccessible settings fail closed", async () => {
  const state = fixture();
  await assert.rejects(verifyProtection(state, "unprotected-environment"));
  state.github.rest.repos.getEnvironment = async () => { throw new Error("Not found"); };
  await assert.rejects(verifyProtection(state, "azure-apply"));
});

test("missing environment returns setup instructions", async () => {
  const state = fixture();
  const error = Object.assign(new Error("Not Found"), {status: 404});
  state.github.rest.repos.getEnvironment = async () => { throw error; };
  await assert.rejects(
    verifyProtection(state, "azure-cybersecurity-prd-plan"),
    /Environment 'azure-cybersecurity-prd-plan' does not exist/,
  );
});

test("approval checks can be disabled explicitly", async () => {
  const state = fixture();
  process.env.REQUIRE_APPROVAL = "false";
  try {
    await verifyProtection(state, "missing-but-temporarily-unprotected");
    await verifyApproval(state, "missing-but-temporarily-unprotected");
  } finally {
    delete process.env.REQUIRE_APPROVAL;
  }
});
