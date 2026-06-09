//! Casbin glue: seeding the policy store and checking a single request.
//!
//! Casbin is embedded — the [`Enforcer`] lives in this process. Policies are persisted to
//! Postgres by the sqlx adapter; `enforce` itself is a synchronous in-memory call.

use anyhow::Result;
use casbin::{CoreApi, Enforcer, MgmtApi, RbacApi};

use crate::domain::{Action, RESOURCE, ROLE_GRANTS, SEED_USERS, is_real_role};

/// Seed the enforcer with the demo's role permissions and user→role assignments.
///
/// Deterministic and idempotent: auto-save is disabled while we clear the in-memory policy,
/// rebuild it, then `save_policy` replaces the Postgres `casbin_rule` table in one shot. Each
/// run therefore leaves exactly the demo policy set, regardless of prior runs.
pub async fn seed_policies(enforcer: &mut Enforcer) -> Result<()> {
    enforcer.enable_auto_save(false);
    enforcer.clear_policy().await?;

    // Permission policies: (role, document, action).
    let mut policies: Vec<Vec<String>> = Vec::new();
    for (role, actions) in ROLE_GRANTS {
        for action in *actions {
            policies.push(vec![
                (*role).to_string(),
                RESOURCE.to_string(),
                action.as_str().to_string(),
            ]);
        }
    }
    enforcer.add_policies(policies).await?;

    // Role assignments: (user, role). `dave` has no real role, so he gets none.
    for user in SEED_USERS.iter() {
        if is_real_role(user.role) {
            enforcer
                .add_role_for_user(user.name, user.role, None)
                .await?;
        }
    }

    enforcer.save_policy().await?;
    Ok(())
}

/// Check whether `actor` may perform `action` on the document resource.
///
/// Casbin's `enforce` is synchronous and takes the request tuple `(sub, obj, act)`.
pub fn check(enforcer: &Enforcer, actor: &str, action: Action) -> Result<bool> {
    Ok(enforcer.enforce((actor, RESOURCE, action.as_str()))?)
}
